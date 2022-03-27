package realip

import (
	"time"

	"go.uber.org/zap"
)

type state struct {
	Refreshed chan bool

	done chan bool

	logger *zap.Logger
}

func (state *state) Start(duration time.Duration, logger *zap.Logger) {

	logger.Info("starting cidr refresh routine")

	state.logger = logger
	state.Refreshed = make(chan bool, 1)
	state.done = make(chan bool, 1)

	go func() {
		ticker := time.NewTicker(duration)
		defer ticker.Stop()

		state.updateDynamicPresets()

		for {
			select {
			case <-ticker.C:
				err := state.updateDynamicPresets()
				if err != nil {
					logger.Error("cidr refresh failed", zap.Error(err))
				}
				state.Refreshed <- true
			case <-state.done:
				logger.Debug("cidr refresh stopped")
				return
			}
		}
	}()

}

func (state *state) Destruct() error {
	state.logger.Debug("destorying realip state")
	if state.done != nil {
		close(state.done)
	}
	return nil
}

func (state *state) updateDynamicPresets() error {

	// refresh presets
	for name, p := range presetRegistry {
		if p.Update != nil {
			start := time.Now()
			newRanges, err := p.Update()
			if err != nil {
				state.logger.Error("failed to update dynamic preset",
					zap.String("name", name),
					zap.Error(err))
			} else {
				p.Ranges = newRanges
				state.logger.Info("refresh completed",
					zap.String("name", name),
					zap.Int("count", len(newRanges)),
					zap.Float64("elapsed", time.Since(start).Seconds()))
			}
		}
	}

	return nil
}
