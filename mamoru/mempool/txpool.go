package mempool

import (
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/event"
)

type TxPool interface {
	SubscribeNewTxsEvent(ch chan<- core.NewTxsEvent) event.Subscription
}
