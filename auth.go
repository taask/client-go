package taask

import (
	"context"
	"encoding/binary"
	"time"

	"github.com/cohix/simplcrypto"

	"github.com/pkg/errors"
	"github.com/taask/client-golang/config"
	"github.com/taask/taask-server/auth"
	sconfig "github.com/taask/taask-server/config"
	"github.com/taask/taask-server/model"
	"github.com/taask/taask-server/service"
)

// Authenticate auths with the taask server and saves the session
func (c *Client) authenticate() error {
	memberUUID := model.NewRunnerUUID()

	keypair, err := simplcrypto.GenerateNewKeyPair()
	if err != nil {
		return errors.Wrap(err, "failed to GenerateNewKeyPair")
	}

	timestamp := time.Now().Unix()

	nonce := make([]byte, 8)
	binary.LittleEndian.PutUint64(nonce, uint64(timestamp))
	hashWithNonce := append(c.localAuth.MemberGroup.AuthHash, nonce...)

	authHashSig, err := keypair.Sign(hashWithNonce)
	if err != nil {
		return errors.Wrap(err, "failed to Sign")
	}

	attempt := &service.AuthMemberRequest{
		UUID:              memberUUID,
		GroupUUID:         c.localAuth.MemberGroup.UUID,
		PubKey:            keypair.SerializablePubKey(),
		AuthHashSignature: authHashSig,
		Timestamp:         timestamp,
	}

	authResp, err := c.client.AuthClient(context.Background(), attempt)
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

	session := config.ActiveSession{
		Session: &auth.Session{
			MemberUUID:          memberUUID,
			GroupUUID:           c.localAuth.MemberGroup.UUID,
			SessionChallengeSig: challengeSig,
		},
		Keypair:            keypair,
		MasterRunnerPubKey: masterRunnerPubKey,
	}

	c.localAuth.ActiveSession = session

	return nil
}

// GenerateAdminGroup generates an admin user group for taask-server
func GenerateAdminGroup() *config.LocalAuthConfig {
	passphrase := auth.GenerateJoinCode() // generate a passphrase for now, TODO: allow user to set passphrase

	adminConfig := generateNewMemberGroup("admin", auth.AdminGroupUUID, passphrase)

	localConfig := &config.LocalAuthConfig{
		ClientAuthConfig: adminConfig,
		Passphrase:       passphrase,
	}

	return localConfig
}

// GenerateDefaultRunnerGroup generates an admin user group for taask-server
func GenerateDefaultRunnerGroup() *config.LocalAuthConfig {
	defaultConfig := generateNewMemberGroup("default", auth.DefaultGroupUUID, "")

	localConfig := &config.LocalAuthConfig{
		ClientAuthConfig: defaultConfig,
	}

	return localConfig
}

func generateNewMemberGroup(name, uuid, passphrase string) sconfig.ClientAuthConfig {
	joinCode := auth.GenerateJoinCode()
	authHash := auth.GroupAuthHash(joinCode, passphrase)

	group := auth.MemberGroup{
		UUID:     uuid,
		Name:     name,
		JoinCode: joinCode,
		AuthHash: authHash,
	}

	adminAuthConfig := sconfig.ClientAuthConfig{
		Version:     sconfig.MemberAuthConfigVersion,
		Type:        sconfig.MemberAuthConfigType,
		MemberGroup: group,
	}

	return adminAuthConfig
}
