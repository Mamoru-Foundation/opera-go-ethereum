# geth-mamoru-core-sdk

This implementation of the geth-mamoru-core-sdk requires the use of `go-ethereum` version > `1.12.0`. 

## Usage
Install the package in an Ethereum-based project

```shell
go get github.com/Mamoru-Foundation/geth-mamoru-core-sdk
```

### For light mode (--syncmode light)

Add the following to import statements in the file `go-ethereum/light/lightchain.go`:

```go
import (
    mamoru "github.com/Mamoru-Foundation/geth-mamoru-core-sdk"
    "github.com/Mamoru-Foundation/geth-mamoru-core-sdk/call_tracer"
)
``` 
Add field Sniffer *mamoru.Sniffer  to  LightChain type in the file `go-ethereum/light/lightchain.go`:

```go
type LightChain struct {
    ...
    Sniffer *mamoru.Sniffer
}
```
and set them in the function `func NewLightChain(...) (*LightChain, error)`

```go
    ...
    lc := &LightChain{
        ...
        Sniffer: mamoru.NewSniffer(), // Add this line
    }
    ...
```


Then, paste the following code into the Ethereum light client file `go-ethereum/light/lightchain.go`:
Insert this code to end of function `InsertHeaderChain(chain []*types.Header, checkFreq int) (int, error)`

```go
	//////////////////////////////////////////////////////////////////
    if !lc.Sniffer.CheckRequirements() {
        return 0, nil
    }
    
    ctx := context.Background()
    
    lastBlock, err := lc.GetBlockByNumber(ctx, block.NumberU64())
    if err != nil {
        return 0, err
    }
    
    parentBlock, err := lc.GetBlockByHash(ctx, block.ParentHash())
    if err != nil {
        return 0, err
    }
    
    stateDb := NewState(ctx, parentBlock.Header(), lc.Odr())
    receipts, err := GetBlockReceipts(ctx, lc.Odr(), lastBlock.Hash(), lastBlock.Number().Uint64())
    if err != nil {
        return 0, err
    }
    
    startTime := time.Now()
    log.Info("Mamoru Eth Sniffer start", "number", block.NumberU64(), "ctx", mamoru.CtxLightchain)
    
    tracer := mamoru.NewTracer(mamoru.NewFeed(lc.Config()))
    tracer.FeedBlock(block)
    tracer.FeedTransactions(block.Number(), block.Time(), block.Transactions(), receipts)
    tracer.FeedEvents(receipts)
    
    //Launch EVM and Collect Call Trace data
    txTrace, err := call_tracer.TraceBlock(ctx, call_tracer.NewTracerConfig(stateDb.Copy(), lc.Config(), lc), lastBlock)
    if err != nil {
        log.Error("Mamoru Eth Sniffer Error", "err", err, "ctx", mamoru.CtxLightchain)
        return 0, err
    }
    for _, call := range txTrace {
        callFrames := call.Result
        tracer.FeedCalTraces(callFrames, block.NumberU64())
    }
    
    tracer.Send(startTime, block.Number(), block.Hash(), mamoru.CtxLightchain)
//////////////////////////////////////////////////////////////////
```

Add the following after creating handler `leth.handler = newClientHandler(config.UltraLightServers, config.UltraLightFraction, checkpoint, leth)`  in the file `eth/les/client.go`


```go
////////////////////////////////////////////////////////
    // Attach Downloader to sniffer
    leth.blockchain.Sniffer.SetDownloader(leth.handler.downloader)
////////////////////////////////////////////////////////
```

### For full/snap mode  (--syncmode full|snap)

Add the following to import statements in the file `go-ethereum/core/blockchain.go`

```go
import (
    mamoru "github.com/Mamoru-Foundation/geth-mamoru-core-sdk"
)
```
Add field `Sniffer *mamoru.Sniffer`  to  `BlockChain` type in the file `go-ethereum/core/blockchain.go`:

```go
type BlockChain struct {
    ...
    Sniffer *mamoru.Sniffer
}
```

and set them in the function `func NewBlockChain(...) (*BlockChain, error)`

```go
    ...
    bc := &BlockChain{
        ...
        Sniffer: mamoru.NewSniffer(), // Add this line
    }
    ...
```

Enable debug mode and insert tracer instance to function `func NewBlockChain()`

```go
    var err error
//////////////////////////////////////////////////////////////
    // Enable Debug mod and Set Mamoru Tracer
    if bc.Sniffer.CheckRequirements() {
        tracer := mamoru.NewCallTracer(false)
        bc.vmConfig.Tracer = tracer
    }
//////////////////////////////////////////////////////////////
    bc.hc, err = NewHeaderChain(db, chainConfig, engine, bc.insertStopped)
```

Insert the main tracer code at the end of the function `func (bc *BlockChain) writeBlockAndSetHead()`

```go
    ...
////////////////////////////////////////////////////////////
    if !mamoru.IsSnifferEnable() || !mamoru.Connect() {
        return 0, nil
    }
    startTime := time.Now()
    log.Info("Mamoru Sniffer start", "number", block.NumberU64(), "ctx", mamoru.CtxBlockchain)
    tracer := mamoru.NewTracer(mamoru.NewFeed(bc.chainConfig))
    tracer.FeedBlock(block)
    tracer.FeedTransactions(block.Number(), block.Time(), block.Transactions(), receipts)
    tracer.FeedEvents(receipts)
    // Collect Call Trace data  from EVM
    if callTracer, ok := bc.GetVMConfig().Tracer.(*mamoru.CallTracer); ok {
        callFrames, err := callTracer.GetResult()
        if err != nil {
            log.Error("Mamoru Sniffer Tracer Error", "err", err, "ctx", mamoru.CtxBlockchain)
            return 0, err
        }
        tracer.FeedCalTraces(callFrames, block.NumberU64())
    }
    tracer.Send(startTime, block.Number(), block.Hash(), mamoru.CtxBlockchain)
////////////////////////////////////////////////////////////
	return status, nil
}
```

Add the following after condition `if eth.handler, err = newHandler(&handlerConfig{...`  in the file `eth/backend.go`

```go
////////////////////////////////////////////////////////
    // Attach downloader to sniffer
    eth.blockchain.Sniffer.SetDownloader(eth.handler.downloader)
////////////////////////////////////////////////////////
```


### For Txpool and full/snap mode  (--syncmode full|snap)

Add the following to import statements in the file `go-ethereum/eth/backend.go`

```go
import (
    mamoru "github.com/Mamoru-Foundation/geth-mamoru-core-sdk"
    "github.com/Mamoru-Foundation/geth-mamoru-core-sdk/mempool"
)
```

Insert the main tracer code in function `func New(stack *node.Node, config *ethconfig.Config) (*Ethereum, error)`

```go
    ...
    eth.txPool = txpool.NewTxPool(config.TxPool, eth.blockchain.Config(), eth.blockchain)
////////////////////////////////////////////////////////
    // Attach txpool sniffer
    sniffer := mempool.NewSniffer(context.Background(), eth.txPool, eth.blockchain, eth.blockchain.Config(),
    mamoru.NewFeed(eth.blockchain.Config()))
    go sniffer.SnifferLoop()
////////////////////////////////////////////////////////
```

### For Txpool and light mode  (--syncmode light)

Add the following in the file `go-ethereum/les/client.go`

```go
	leth.txPool = light.NewTxPool(leth.chainConfig, leth.blockchain, leth.relay)
////////////////////////////////////////////////////////
	// Attach LightTxpool sniffer
	mempool.NewLightSniffer(context.Background(), leth.txPool, leth.blockchain, chainConfig)
////////////////////////////////////////////////////////
```


### Build the project:

```shell
make geth
```

Export Mamoru Environment Variables

```shell
export MAMORU_CHAIN_TYPE=<chain-type>
export MAMORU_SNIFFER_ENABLE=true
export MAMORU_PRIVATE_KEY=<private-key>
export MAMORU_CHAIN_ID=<validations-chain-id>
export MAMORU_ENDPOINT="https://validation-chain-url"
```


Run the following command to check if it works

```shell
 geth --syncmode light --goerli
```

It's really easy, enjoy

#### Current version Ethereum client:

go-ethereum@v1.12.0