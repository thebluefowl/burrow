package progress

import (
	"fmt"
	"os"

	"github.com/schollz/progressbar/v3"
)

// Constants for progress bar configuration
const (
	progressBarWidth       = 40
	progressBarThrottle    = 65 * 1000000
	progressBarSpinnerType = 14
)

// createProgressBar creates a standardized progress bar
func CreateProgressBar(description string) *progressbar.ProgressBar {
	return progressbar.NewOptions64(
		-1, // Unknown size
		progressbar.OptionSetDescription(description),
		progressbar.OptionSetWriter(os.Stderr),
		progressbar.OptionShowBytes(true),
		progressbar.OptionSetWidth(progressBarWidth),
		progressbar.OptionThrottle(progressBarThrottle),
		progressbar.OptionShowCount(),
		progressbar.OptionOnCompletion(func() {
			fmt.Fprint(os.Stderr, "\n")
		}),
		progressbar.OptionSpinnerType(progressBarSpinnerType),
		progressbar.OptionFullWidth(),
		progressbar.OptionSetRenderBlankState(true),
	)
}
