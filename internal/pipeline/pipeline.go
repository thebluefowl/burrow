package pipeline

import (
	"context"
	"io"
	"sync"
)

// Stage transforms data from r → w. For the first stage, r may be nil.
// For the last stage, w may be io.Discard if unused.
type Stage func(ctx context.Context, r io.Reader, w io.Writer) error

// PipeGraph wires stages together with io.Pipes.
// Cancels all stages on first error and closes all pipes with that error.
func PipeGraph(ctx context.Context, stages ...Stage) error {
	return pipeGraph(ctx, nil, stages...)
}

// PipeGraphWithSink wires stages together with io.Pipes and provides a final sink writer
// that receives output from the last stage.
// Cancels all stages on first error and closes all pipes with that error.
func PipeGraphWithSink(ctx context.Context, sink io.Writer, stages ...Stage) error {
	return pipeGraph(ctx, sink, stages...)
}

func pipeGraph(ctx context.Context, sink io.Writer, stages ...Stage) error {
	if len(stages) == 0 {
		return nil
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	type pipePair struct {
		r *io.PipeReader
		w *io.PipeWriter
	}

	pipes := make([]pipePair, len(stages)-1)
	for i := range pipes {
		r, w := io.Pipe()
		pipes[i] = pipePair{r, w}
	}

	var wg sync.WaitGroup
	errCh := make(chan error, 1) // only need first error

	closeAllWithError := func(err error) {
		for _, p := range pipes {
			_ = p.r.CloseWithError(err)
			_ = p.w.CloseWithError(err)
		}
	}

	for i, stage := range stages {
		wg.Add(1)
		go func(i int, s Stage) {
			defer wg.Done()

			var r io.Reader
			var w io.Writer

			if i > 0 {
				r = pipes[i-1].r
			}
			if i < len(pipes) {
				w = pipes[i].w
			} else if sink != nil {
				w = sink
			}

			if err := s(ctx, r, w); err != nil {
				select {
				case errCh <- err:
					closeAllWithError(err)
					cancel()
				default:
					// another stage already reported an error
				}
				return
			}

			if i < len(pipes) {
				_ = pipes[i].w.Close()
			}
		}(i, stage)
	}

	wg.Wait()
	select {
	case err := <-errCh:
		return err
	default:
		return nil
	}
}
