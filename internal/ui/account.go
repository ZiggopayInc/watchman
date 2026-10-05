package ui

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

// passwordPath is relative, so the request goes to the same site the page was loaded from.
const passwordPath = "/v2/account/password"

// AccountContainer lets the signed-in user change their own password. The server makes the change with the
// user's Cognito session (see internal/account), so this page only sends the two passwords.
func AccountContainer(ctx context.Context) fyne.CanvasObject {
	current := widget.NewPasswordEntry()
	current.SetPlaceHolder("Current password")
	proposed := widget.NewPasswordEntry()
	proposed.SetPlaceHolder("New password")
	repeated := widget.NewPasswordEntry()
	repeated.SetPlaceHolder("Repeat new password")

	status := widget.NewLabel("")
	status.Wrapping = fyne.TextWrapWord
	status.Hide()

	var saveBtn *widget.Button
	saveBtn = widget.NewButton("Change password", func() {
		fail := func(message string) {
			status.Importance = widget.DangerImportance
			status.SetText(message)
			status.Show()
		}
		if current.Text == "" || proposed.Text == "" {
			fail("Enter your current password and a new one.")
			return
		}
		if proposed.Text != repeated.Text {
			fail("The new passwords do not match.")
			return
		}

		saveBtn.Disable()
		status.Importance = widget.LowImportance
		status.SetText("Changing your password…")
		status.Show()

		previous, next := current.Text, proposed.Text
		go func() {
			message, ok := changePassword(ctx, previous, next)
			fyne.Do(func() {
				saveBtn.Enable()
				if ok {
					current.SetText("")
					proposed.SetText("")
					repeated.SetText("")
					status.Importance = widget.SuccessImportance
				} else {
					status.Importance = widget.DangerImportance
				}
				status.SetText(message)
				status.Show()
			})
		}()
	})

	return container.NewPadded(container.NewVBox(
		widget.NewLabelWithStyle("Change your password", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		current,
		proposed,
		repeated,
		saveBtn,
		status,
	))
}

// changePassword returns the message to show and whether the change worked.
func changePassword(ctx context.Context, previous, proposed string) (string, bool) {
	payload, err := json.Marshal(map[string]string{"previousPassword": previous, "proposedPassword": proposed})
	if err != nil {
		return "The password could not be sent.", false
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, passwordPath, bytes.NewReader(payload))
	if err != nil {
		return "The password could not be sent.", false
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "Could not reach the server. Check your connection and try again.", false
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		return "Your password has been changed.", true
	}
	var failure struct {
		Error string `json:"error"`
	}
	_ = json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&failure)
	if failure.Error == "" {
		return "The password could not be changed (" + resp.Status + ").", false
	}
	return failure.Error, false
}
