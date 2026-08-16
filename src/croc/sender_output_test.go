package croc

import (
	"bytes"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type sendInstructionRecorder struct {
	buffer         bytes.Buffer
	outputCalls    int
	clipboardCalls int
	qrCalls        int
	clipboardSet   bool
	qrSet          bool
}

func (r *sendInstructionRecorder) presenter() sendInstructionPresenter {
	return sendInstructionPresenter{
		output: func() (io.Writer, bool) {
			r.outputCalls++
			return &r.buffer, false
		},
		copyToClipboard: func(value string, _ bool, _ bool) {
			r.clipboardCalls++
			r.clipboardSet = value != ""
		},
		showQRCode: func(value string) {
			r.qrCalls++
			r.qrSet = value != ""
		},
	}
}

func TestFormatSendInstructionsPlain(t *testing.T) {
	const (
		secret = "acid-pink-fostered-succeeding"
		flags  = "--relay relay.example:9009 "
		webURL = "https://getcroc.com/?code=acid-pink-fostered-succeeding"
	)

	want := `Code is: acid-pink-fostered-succeeding

On the other computer run:
(For Windows)
    croc --relay relay.example:9009 acid-pink-fostered-succeeding
(For Linux/macOS)
    CROC_SECRET="acid-pink-fostered-succeeding" croc --relay relay.example:9009 

Or receive in a browser:
    https://getcroc.com/?code=acid-pink-fostered-succeeding
`

	got := formatSendInstructions(secret, flags, webURL, false)
	if got != want {
		t.Fatalf("plain instructions differ:\nwant: %q\n got: %q", want, got)
	}
	if strings.Contains(got, "\x1b") {
		t.Fatalf("plain instructions contain an ANSI escape: %q", got)
	}
}

func TestFormatSendInstructionsColor(t *testing.T) {
	const (
		secret = "acid-pink-fostered-succeeding"
		flags  = "--relay relay.example:9009 "
		webURL = "https://getcroc.com/?code=acid-pink-fostered-succeeding"
	)

	styledSecret := secretColorPrefix + secret + colorReset
	want := "Code is: " + styledSecret + `

On the other computer run:
(For Windows)
    croc --relay relay.example:9009 ` + styledSecret + `
(For Linux/macOS)
    CROC_SECRET="` + styledSecret + `" croc --relay relay.example:9009 

Or receive in a browser:
    https://getcroc.com/?code=acid-pink-fostered-succeeding
`

	got := formatSendInstructions(secret, flags, webURL, true)
	if got != want {
		t.Fatalf("colored instructions differ:\nwant: %q\n got: %q", want, got)
	}
	if count := strings.Count(got, secretColorPrefix); count != 3 {
		t.Fatalf("color prefix count = %d; want 3", count)
	}
	urlSection := got[strings.Index(got, "Or receive in a browser:"):]
	if strings.Contains(urlSection, "\x1b") {
		t.Fatal("browser URL contains an ANSI escape")
	}
}

func TestFormatClipboardTextHasNoStyling(t *testing.T) {
	const secret = "acid-pink-fostered-succeeding"

	tests := []struct {
		name     string
		extended bool
		want     string
	}{
		{name: "code only", want: secret},
		{
			name:     "extended command",
			extended: true,
			want:     `CROC_SECRET="acid-pink-fostered-succeeding" croc --relay relay.example:9009`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := formatClipboardText(secret, "--relay relay.example:9009 ", test.extended)
			if got != test.want {
				t.Fatalf("clipboard text = %q; want %q", got, test.want)
			}
			if strings.Contains(got, "\x1b") {
				t.Fatalf("clipboard text contains an ANSI escape: %q", got)
			}
		})
	}
}

func TestPresentSendInstructionsSuppressed(t *testing.T) {
	recorder := new(sendInstructionRecorder)
	client := &Client{
		Options: Options{
			SharedSecret:             "test-only-share-secret",
			RelayAddress:             "relay.example.test:9010",
			RelayPassword:            "test-only-relay-password",
			ExtendedClipboard:        true,
			ShowQrCode:               true,
			SuppressSendInstructions: true,
		},
		sendInstructionPresenter: recorder.presenter(),
	}

	client.presentSendInstructions()

	if recorder.outputCalls != 0 || recorder.buffer.Len() != 0 {
		t.Fatal("suppressed instructions accessed the output writer")
	}
	if recorder.clipboardCalls != 0 {
		t.Fatal("suppressed instructions accessed the clipboard")
	}
	if recorder.qrCalls != 0 {
		t.Fatal("suppressed instructions generated a QR code")
	}
}

func TestPresentSendInstructionsDefaultBehavior(t *testing.T) {
	recorder := new(sendInstructionRecorder)
	client := &Client{
		Options: Options{
			SharedSecret:      "test-only-share-secret",
			RelayAddress:      "relay.example.test:9010",
			RelayPassword:     "test-only-relay-password",
			ExtendedClipboard: true,
			ShowQrCode:        true,
		},
		sendInstructionPresenter: recorder.presenter(),
	}

	client.presentSendInstructions()

	if recorder.outputCalls != 1 || recorder.buffer.Len() == 0 {
		t.Fatal("default instructions were not written")
	}
	for _, marker := range []string{"Code is:", "--pass ", "https://getcroc.com/"} {
		if !strings.Contains(recorder.buffer.String(), marker) {
			t.Fatalf("default instructions are missing %s", marker)
		}
	}
	if recorder.clipboardCalls != 1 || !recorder.clipboardSet {
		t.Fatal("default instructions did not provide clipboard text")
	}
	if recorder.qrCalls != 1 || !recorder.qrSet {
		t.Fatal("default instructions did not provide QR content")
	}
}

func TestPresentSendInstructionsDisableClipboardOnly(t *testing.T) {
	recorder := new(sendInstructionRecorder)
	client := &Client{
		Options: Options{
			SharedSecret:     "test-only-share-secret",
			DisableClipboard: true,
		},
		sendInstructionPresenter: recorder.presenter(),
	}

	client.presentSendInstructions()

	if recorder.outputCalls != 1 || recorder.buffer.Len() == 0 {
		t.Fatal("disabling the clipboard also suppressed instructions")
	}
	if recorder.clipboardCalls != 0 {
		t.Fatal("clipboard callback was called while disabled")
	}
}

func TestClientSendInstructionsIntegration(t *testing.T) {
	fileName := filepath.Join(t.TempDir(), "payload.txt")
	if err := os.WriteFile(fileName, []byte("test-only-payload"), 0o600); err != nil {
		t.Fatal("create test payload")
	}

	tests := []struct {
		name       string
		suppress   bool
		wantCalls  int
		wantOutput bool
		client     *Client
		recorder   *sendInstructionRecorder
	}{
		{name: "default presentation", wantCalls: 1, wantOutput: true},
		{name: "suppressed presentation", suppress: true},
	}

	for i := range tests {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal("reserve loopback relay address")
		}
		relayAddress := listener.Addr().String()
		_, relayPort, err := net.SplitHostPort(relayAddress)
		if err != nil {
			listener.Close()
			t.Fatal("split loopback relay address")
		}
		if err := listener.Close(); err != nil {
			t.Fatal("release loopback relay address")
		}

		client, err := New(Options{
			IsSender:                 true,
			SharedSecret:             "8123-testingthecroc2",
			RelayAddress:             relayAddress,
			RelayAddress6:            "",
			RelayPorts:               []string{relayPort},
			RelayPassword:            "test-only-relay-password",
			NoPrompt:                 true,
			DisableLocal:             true,
			Curve:                    "siec",
			HashAlgorithm:            "xxhash",
			ShowQrCode:               true,
			ExtendedClipboard:        true,
			SuppressSendInstructions: tests[i].suppress,
		})
		if err != nil {
			t.Fatal("create sender client")
		}
		recorder := new(sendInstructionRecorder)
		client.sendInstructionPresenter = recorder.presenter()
		tests[i].client = client
		tests[i].recorder = recorder
	}

	for i := range tests {
		test := &tests[i]
		t.Run(test.name, func(t *testing.T) {
			filesInfo, emptyFolders, totalFolders, err := GetFilesInfo([]string{fileName}, false, false, nil)
			if err != nil {
				t.Fatal("collect test payload")
			}

			sendErr := test.client.Send(filesInfo, emptyFolders, totalFolders)
			select {
			case <-test.client.stop.stopChan:
			case <-time.After(time.Second):
				t.Fatal("sender shutdown did not finish")
			}
			if sendErr == nil {
				t.Fatal("send unexpectedly reached an unavailable loopback relay")
			}

			if test.recorder.outputCalls != test.wantCalls || test.recorder.clipboardCalls != test.wantCalls || test.recorder.qrCalls != test.wantCalls {
				t.Fatal("Client.Send did not apply the configured instruction presentation")
			}
			if gotOutput := test.recorder.buffer.Len() > 0; gotOutput != test.wantOutput {
				t.Fatal("Client.Send instruction output state was unexpected")
			}
		})
	}
}
