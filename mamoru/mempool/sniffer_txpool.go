package mempool

import (
	"context"
	"math/big"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"

	"github.com/ethereum/go-ethereum/mamoru"
)

type blockChain interface {
	core.ChainContext
	CurrentBlock() *types.Block
	GetBlock(hash common.Hash, number uint64) *types.Block
	StateAt(root common.Hash) (*state.StateDB, error)
	State() (*state.StateDB, error)

	SubscribeChainHeadEvent(ch chan<- core.ChainHeadEvent) event.Subscription
	SubscribeChainEvent(ch chan<- core.ChainEvent) event.Subscription
}

type SnifferBackend struct {
	txPool      TxPool
	chain       blockChain
	chainConfig *params.ChainConfig
	feeder      mamoru.Feeder

	newHeadEvent chan core.ChainHeadEvent
	newTxsEvent  chan core.NewTxsEvent

	chEv chan core.ChainEvent

	TxSub   event.Subscription
	headSub event.Subscription

	chEvSub event.Subscription

	ctx     context.Context
	mu      sync.RWMutex
	sniffer *mamoru.Sniffer
}

func NewSniffer(ctx context.Context, txPool TxPool, chain blockChain, chainConfig *params.ChainConfig, feeder mamoru.Feeder) *SnifferBackend {
	sb := &SnifferBackend{
		txPool:      txPool,
		chain:       chain,
		chainConfig: chainConfig,

		newTxsEvent:  make(chan core.NewTxsEvent, 1024),
		newHeadEvent: make(chan core.ChainHeadEvent, 10),

		chEv: make(chan core.ChainEvent, 10),

		feeder: feeder,

		ctx: ctx,
		mu:  sync.RWMutex{},

		sniffer: mamoru.NewSniffer(),
	}
	sb.TxSub = sb.SubscribeNewTxsEvent(sb.newTxsEvent)
	sb.headSub = sb.SubscribeChainHeadEvent(sb.newHeadEvent)
	sb.chEvSub = sb.SubscribeChainEvent(sb.chEv)

	go sb.SnifferLoop()

	return sb
}

func (bc *SnifferBackend) SubscribeNewTxsEvent(ch chan<- core.NewTxsEvent) event.Subscription {
	return bc.txPool.SubscribeNewTxsEvent(ch)
}

// SubscribeChainHeadEvent registers a subscription of ChainHeadEvent.
func (bc *SnifferBackend) SubscribeChainHeadEvent(ch chan<- core.ChainHeadEvent) event.Subscription {
	return bc.chain.SubscribeChainHeadEvent(ch)
}

func (bc *SnifferBackend) SubscribeChainEvent(ch chan<- core.ChainEvent) event.Subscription {
	return bc.chain.SubscribeChainEvent(ch)
}

func (bc *SnifferBackend) SnifferLoop() {
	defer func() {
		bc.TxSub.Unsubscribe()
		bc.headSub.Unsubscribe()
		bc.chEvSub.Unsubscribe()
	}()

	ctx, cancel := context.WithCancel(bc.ctx)
	var block = bc.chain.CurrentBlock()

	for {
		select {
		case <-bc.ctx.Done():
		case <-bc.TxSub.Err():
		case <-bc.headSub.Err():
		case <-bc.chEvSub.Err():
			cancel()
			return

		case newTx := <-bc.newTxsEvent:
			go bc.process(ctx, block, newTx.Txs)

		case newHead := <-bc.newHeadEvent:
			if newHead.Block != nil && newHead.Block.NumberU64() > block.NumberU64() {
				log.Info("New core.ChainHeadEvent", "number", newHead.Block.NumberU64(), "ctx", mamoru.CtxTxpool)
				bc.mu.RLock()
				block = newHead.Block
				bc.mu.RUnlock()
			}

		case newChEv := <-bc.chEv:
			if newChEv.Block != nil && newChEv.Block.NumberU64() > block.NumberU64() {
				log.Info("New core.ChainEvent", "number", newChEv.Block.NumberU64(), "ctx", mamoru.CtxTxpool)
				bc.mu.RLock()
				block = newChEv.Block
				bc.mu.RUnlock()
			}
		}
	}
}

func (bc *SnifferBackend) process(ctx context.Context, block *types.Block, txs types.Transactions) {
	if ctx.Err() != nil || !bc.sniffer.CheckRequirements() {
		return
	}
	blockNumber := block.NumberU64()
	log.Info("Mamoru start", "number", blockNumber, "txs", txs.Len(), "ctx", mamoru.CtxTxpool)
	startTime := time.Now()

	// Create tracer context
	tracer := mamoru.NewTracer(bc.feeder)

	// Set txpool context
	tracer.SetTxpoolCtx()

	var receipts types.Receipts
	var callTraces []*mamoru.CallFrame

	stateDb, err := bc.chain.StateAt(block.Header().Root)
	if err != nil {
		log.Error("Mamoru State", "number", blockNumber, "err", err, "ctx", mamoru.CtxTxpool)
	}

	stateDb = stateDb.Copy()
	block.Header().BaseFee = new(big.Int).SetUint64(0)

	for _, tx := range txs {
		callStackTracer := mamoru.NewCallStackTracer(types.Transactions{tx}, mamoru.RandStr(8), false, mamoru.CtxTxpool)
		chCtx := core.ChainContext(bc.chain)

		//stateDb.SetTxContext(tx.Hash(), index)

		from, err := types.Sender(types.LatestSigner(bc.chainConfig), tx)
		if err != nil {
			log.Error("types.Sender", "number", blockNumber, "err", err, "ctx", mamoru.CtxTxpool)
		}

		if tx.Nonce() != stateDb.GetNonce(from) {
			stateDb.SetNonce(from, tx.Nonce())
		}

		receipt, err := core.ApplyTransaction(bc.chainConfig, chCtx, &from, new(core.GasPool).AddGas(tx.Gas()), stateDb, block.Header(), tx,
			new(uint64), vm.Config{Debug: true, Tracer: callStackTracer, NoBaseFee: true})
		if err != nil {
			log.Error("Mamoru Tx Apply", "number", blockNumber, "err", err,
				"tx.hash", tx.Hash().String(), "ctx", mamoru.CtxTxpool)
			break
		}

		// Clean receipt
		cleanReceiptAndLogs(receipt)

		receipts = append(receipts, receipt)

		callFrames, err := callStackTracer.TakeResult()
		if err != nil {
			log.Error("Mamoru tracer result", "number", blockNumber, "err", err, "ctx", mamoru.CtxTxpool)
			break
		}

		var bytesLength int
		for i := 0; i < len(callFrames); i++ {
			bytesLength += len(callFrames[i].Input)
		}

		callTraces = append(callTraces, callFrames...)
	}

	log.Info("Mamoru collected", "number", blockNumber, "txs", txs.Len(),
		"receipts", receipts.Len(), "callTraces", len(callTraces), "callFrames.input.len", InputByteLength(callTraces), "ctx", mamoru.CtxTxpool)

	tracer.FeedCallTraces(callTraces, block.NumberU64())
	tracer.FeedTransactions(block.Number(), block.Time(), txs, receipts)
	tracer.FeedEvents(receipts)
	tracer.Send(startTime, block.Number(), block.Hash(), mamoru.CtxTxpool)
}

func cleanReceiptAndLogs(receipt *types.Receipt) {
	receipt.BlockNumber = big.NewInt(0)
	receipt.BlockHash = common.Hash{}
	for _, l := range receipt.Logs {
		l.BlockNumber = 0
		l.BlockHash = common.Hash{}
	}
}

func InputByteLength(callTraces []*mamoru.CallFrame) int {
	var bytesLength int
	for i := 0; i < len(callTraces); i++ {
		bytesLength += len(callTraces[i].Input)
	}
	return bytesLength
}
