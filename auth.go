package taask

import (
	"context"
	"encoding/binary"
	"io/ioutil"
	"path/filepath"
	"time"

	"github.com/cohix/simplcrypto"

	"github.com/pkg/errors"
	"github.com/taask/taask-server/auth"
	"github.com/taask/taask-server/config"
	"github.com/taask/taask-server/model"
	"github.com/taask/taask-server/service"
	yaml "gopkg.in/yaml.v2"
)

// LocalAuthConfig includes everything needed to auth with a member group
type LocalAuthConfig struct {
	config.ClientAuthConfig
	Passphrase    string
	ActiveSession activeSession `yaml:"-"`
}

type activeSession struct {
	*auth.Session      `yaml:"-"`
	Keypair            *simplcrypto.KeyPair `yaml:"-"`
	MasterRunnerPubKey *simplcrypto.KeyPair `yaml:"-"`
}

// Authenticate auths with the taask server and saves the session
func (la *LocalAuthConfig) Authenticate(client service.TaskServiceClient) error {
	memberUUID := model.NewRunnerUUID()

	keypair, err := simplcrypto.GenerateNewKeyPair()
	if err != nil {
		return errors.Wrap(err, "failed to GenerateNewKeyPair")
	}

	timestamp := time.Now().Unix()

	nonce := make([]byte, 8)
	binary.LittleEndian.PutUint64(nonce, uint64(timestamp))
	hashWithNonce := append(la.AdminGroup.AuthHash, nonce...)

	authHashSig, err := keypair.Sign(hashWithNonce)
	if err != nil {
		return errors.Wrap(err, "failed to Sign")
	}

	attempt := &service.AuthMemberRequest{
		UUID:              memberUUID,
		GroupUUID:         la.AdminGroup.UUID,
		PubKey:            keypair.SerializablePubKey(),
		AuthHashSignature: authHashSig,
		Timestamp:         timestamp,
	}

	authResp, err := client.AuthClient(context.Background(), attempt)
	if err != nil {
		return errors.Wrap(err, "failed to AuthClient")
	}

	challengeBytes, err := keypair.Decrypt(authResp.EncChallenge)
	if err != nil {
		return errors.Wrap(err, "failed to Decrypt challenge")
	}

	masterRunnerPubKey, err := simplcrypto.KeyPairFromSerializedPubKey(authResp.MasterPubKey)
	if err != nil {
		return errors.Wrap(err, "failed to KeyPairFromSerializablePubKey")
	}

	challengeSig, err := keypair.Sign(challengeBytes)
	if err != nil {
		return errors.Wrap(err, "failed to Sign challenge")
	}

	session := activeSession{
		Session: &auth.Session{
			MemberUUID:          memberUUID,
			GroupUUID:           la.AdminGroup.UUID,
			SessionChallengeSig: challengeSig,
		},
		Keypair:            keypair,
		MasterRunnerPubKey: masterRunnerPubKey,
	}

	la.ActiveSession = session

	return nil
}

// GroupKey returns the key for a group
func (la *LocalAuthConfig) GroupKey() (*simplcrypto.SymKey, error) {
	return auth.GroupDerivedKey(la.Passphrase)
}

// WriteServerConfig writes the admin groups's auth file to disk
func (la *LocalAuthConfig) WriteServerConfig(path string) error {
	serverConfigPath := filepath.Join(config.DefaultConfigDir(), "client-auth.yaml")

	return la.ClientAuthConfig.WriteYAML(serverConfigPath)
}

// WriteYAML writes the YAML marshalled config to disk
func (la *LocalAuthConfig) WriteYAML(filepath string) error {
	rawYAML, err := yaml.Marshal(la)
	if err != nil {
		return errors.Wrap(err, "failed to yaml.Marshal")
	}

	if err := ioutil.WriteFile(filepath, rawYAML, 0666); err != nil {
		return errors.Wrap(err, "failed to WriteFile")
	}

	return nil
}

// GenerateAdminGroup generates an admin user group for taask-server
func GenerateAdminGroup() *LocalAuthConfig {
	passphrase := auth.GenerateJoinCode() // generate a passphrase for now, TODO: allow user to set passphrase

	adminConfig := generateAdminGroup(passphrase)

	localConfig := &LocalAuthConfig{
		ClientAuthConfig: adminConfig,
		Passphrase:       passphrase,
	}

	return localConfig
}

func generateAdminGroup(passphrase string) config.ClientAuthConfig {
	joinCode := auth.GenerateJoinCode()
	authHash := auth.GroupAuthHash(joinCode, passphrase)

	group := auth.MemberGroup{
		UUID:     auth.AdminGroupUUID,
		Name:     "admin",
		JoinCode: joinCode,
		AuthHash: authHash,
	}

	adminAuthConfig := config.ClientAuthConfig{
		Version:    config.ClientAuthConfigVersion,
		Type:       config.ClientAuthConfigType,
		AdminGroup: group,
	}

	return adminAuthConfig
}
