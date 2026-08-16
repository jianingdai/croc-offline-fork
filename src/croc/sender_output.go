package croc

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/schollz/croc/v10/src/models"
	"github.com/schollz/croc/v10/src/termui"
)

const (
	secretColorPrefix = termui.Yellow
	colorReset        = termui.Reset
)

type sendInstructionPresenter struct {
	output          func() (io.Writer, bool)
	copyToClipboard func(string, bool, bool)
	showQRCode      func(string)
}

func defaultSendInstructionPresenter() sendInstructionPresenter {
	return sendInstructionPresenter{
		output: func() (io.Writer, bool) {
			return termui.Output(os.Stderr)
		},
		copyToClipboard: copyToClipboard,
		showQRCode:      showReceiveCommandQrCode,
	}
}

func (c *Client) presentSendInstructions() {
	if c.Options.SuppressSendInstructions {
		return
	}

	presenter := c.sendInstructionPresenter
	if presenter.output == nil {
		presenter = defaultSendInstructionPresenter()
	}

	flags := &strings.Builder{}
	if c.Options.RelayAddress != models.DEFAULT_RELAY && !c.Options.OnlyLocal {
		flags.WriteString("--relay " + c.Options.RelayAddress + " ")
	}
	if c.Options.RelayPassword != models.DEFAULT_PASSPHRASE {
		flags.WriteString("--pass " + c.Options.RelayPassword + " ")
	}
	webURL := webReceiveURL(c.Options.SharedSecret)
	output, colorEnabled := presenter.output()
	fmt.Fprint(output, formatSendInstructions(c.Options.SharedSecret, flags.String(), webURL, colorEnabled))
	if !c.Options.DisableClipboard && presenter.copyToClipboard != nil {
		clipboardText := formatClipboardText(c.Options.SharedSecret, flags.String(), c.Options.ExtendedClipboard)
		presenter.copyToClipboard(clipboardText, c.Options.Quiet, c.Options.ExtendedClipboard)
	}
	if c.Options.ShowQrCode && presenter.showQRCode != nil {
		presenter.showQRCode(webURL)
	}
}

func colorSecret(secret string, enabled bool) string {
	if !enabled {
		return secret
	}
	return termui.Secret(secret, true)
}

func colorQuotedSecret(secret string, enabled bool) string {
	quoted := strconv.Quote(secret)
	if !enabled {
		return quoted
	}
	return quoted[:1] + colorSecret(quoted[1:len(quoted)-1], true) + quoted[len(quoted)-1:]
}

func formatSendInstructions(secret, flags, webURL string, colorEnabled bool) string {
	return fmt.Sprintf(`Code is: %[1]s

On the other computer run:
(For Windows)
    croc %[2]s%[1]s
(For Linux/macOS)
    CROC_SECRET=%[3]s croc %[2]s

Or receive in a browser:
    %[4]s
`, colorSecret(secret, colorEnabled), flags, colorQuotedSecret(secret, colorEnabled), webURL)
}

func formatClipboardText(secret, flags string, extended bool) string {
	if !extended {
		return secret
	}
	return fmt.Sprintf("CROC_SECRET=%q croc %s", secret, strings.TrimSpace(flags))
}
