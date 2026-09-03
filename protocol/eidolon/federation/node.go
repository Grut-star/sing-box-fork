package federation

import (
	"time"
	"github.com/sagernet/sing-box/log"
)

// NodeSyncer работает на прокси-узле, синхронизируя секреты с Опорой
type NodeSyncer struct {
	client     *EidolonClient
	updateFunc func(newSecret, newDest string)
	interval   time.Duration
	logger     log.ContextLogger
	stopChan   chan struct{}
}

func NewNodeSyncer(oporaURL, token, pubKeyHex string, interval time.Duration, logger log.ContextLogger, updateFunc func(string, string)) (*NodeSyncer, error) {
	c, err := NewEidolonClient(oporaURL, token, pubKeyHex)
	if err != nil {
		return nil, err
	}

	return &NodeSyncer{
		client:     c,
		updateFunc: updateFunc,
		interval:   interval,
		logger:     logger,
		stopChan:   make(chan struct{}),
	}, nil
}

func (s *NodeSyncer) Start() {
	// Первичная синхронизация перед запуском цикла
	s.sync()

	ticker := time.NewTicker(s.interval)
	go func() {
		for {
			select {
			case <-ticker.C:
				s.sync()
			case <-s.stopChan:
				ticker.Stop()
				return
			}
		}
	}()
}

func (s *NodeSyncer) Stop() {
	close(s.stopChan)
}

func (s *NodeSyncer) sync() {
	state, err := s.client.FetchInitialConfig()
	if err != nil {
		s.logger.Error("Federation Sync failed (keeping current keys): ", err)
		return
	}

	// Опционально: можно искать свой IP в state.Nodes, чтобы взять индивидуальный Dest,
	// но для простоты обновляем глобальный MasterSecret
	s.updateFunc(state.MasterSecret, "")
	s.logger.Info("Federation state updated successfully. Signature verified.")
}