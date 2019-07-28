package bot_sample

import (
	cloudkms "cloud.google.com/go/kms/apiv1"
	"context"
	"encoding/json"
	"fmt"
	"github.com/kelseyhightower/envconfig"
	"github.com/line/line-bot-sdk-go/linebot"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
	"io/ioutil"
	"log"
	"net/http"
)

var (
	secrets Secrets
)

type Secrets struct {
	LineChannelSecret      string `json:"line_channel_secret"`
	LineChannelAccessToken string `json:"line_channel_access_token"`
}

func init() {
	secretsJson, err := decryptLineSecrets()
	if err != nil {
		log.Fatal("failed decrypt secrets", err)
		return
	}
	if err := json.Unmarshal(secretsJson, &secrets); err != nil {
		log.Fatal("failed json unmarshal secrets", err)
		return
	}
}

func Webhook(w http.ResponseWriter, r *http.Request) {
	client, err := linebot.New(secrets.LineChannelSecret, secrets.LineChannelAccessToken)
	if err != nil {
		http.Error(w, "Error init client", http.StatusBadRequest)
		log.Fatal(err)
		return
	}
	events, err := client.ParseRequest(r)
	if err != nil {
		http.Error(w, "Error parse request", http.StatusBadRequest)
		log.Fatal(err)
		return
	}
	for _, e := range events {
		switch e.Type {
		case linebot.EventTypeMessage:
			message := linebot.NewTextMessage("Test")
			_, err := client.ReplyMessage(e.ReplyToken, message).Do()
			if err != nil {
				log.Println(err)
				continue
			}
		}
	}
	_, err = fmt.Fprint(w, "ok")
	if err != nil {
		log.Fatal(err)
	}
}

func decryptLineSecrets() ([]byte, error) {
	enc, err := ioutil.ReadFile("secrets.json.enc")
	if err != nil {
		return nil, err
	}
	return decryptSymmetric(decryptKeyName(), enc)
}

func decryptKeyName() string {
	type Env struct {
		GcpProjectId          string `split_words:"true"`
		KmsKeyRingName        string `split_words:"true"`
		KmsLineSecretsKeyName string `split_words:"true"`
	}

	var env Env
	if err := envconfig.Process("", &env); err != nil {
		log.Fatal(err)
	}

	return fmt.Sprintf(
		"projects/%s/locations/global/keyRings/%s/cryptoKeys/%s",
		env.GcpProjectId,
		env.KmsKeyRingName,
		env.KmsLineSecretsKeyName,
	)
}

// @see https://cloud.google.com/kms/docs/re-encrypt-data?hl=ja#kms-howto-encrypt-go
//
// decrypt will decrypt the input ciphertext bytes using the specified symmetric key
// example keyName: "projects/PROJECT_ID/locations/global/keyRings/RING_ID/cryptoKeys/KEY_ID"
func decryptSymmetric(keyName string, ciphertext []byte) ([]byte, error) {
	ctx := context.Background()
	client, err := cloudkms.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, err
	}

	// Build the request.
	req := &kmspb.DecryptRequest{
		Name:       keyName,
		Ciphertext: ciphertext,
	}
	// Call the API.
	resp, err := client.Decrypt(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp.Plaintext, nil
}
