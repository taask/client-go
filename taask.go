package taask

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/cohix/simplcrypto"

	log "github.com/cohix/simplog"
	"github.com/pkg/errors"
	"github.com/taask/taask-server/model"
	"github.com/taask/taask-server/service"
	"google.golang.org/grpc"
)

// Client describes a taask client
type Client struct {
	client             service.TaskServiceClient
	masterRunnerPubKey *simplcrypto.KeyPair
	taskKeyPairs       map[string]*simplcrypto.KeyPair
	taskKeys           map[string]*simplcrypto.SymKey
	keyLock            *sync.Mutex
}

// NewClient creates a Client
func NewClient(addr, port string) (*Client, error) {
	conn, err := grpc.Dial(fmt.Sprintf("%s:%s", addr, port), grpc.WithInsecure())
	if err != nil {
		return nil, errors.Wrap(err, "failed to Dial")
	}

	client := &Client{
		taskKeyPairs: make(map[string]*simplcrypto.KeyPair),
		keyLock:      &sync.Mutex{},
	}

	client.client = service.NewTaskServiceClient(conn)

	authResp, err := client.client.AuthClient(context.Background(), &service.AuthClientRequest{})
	if err != nil {
		return nil, errors.Wrap(err, "failed to AuthClient")
	}

	client.masterRunnerPubKey, err = simplcrypto.KeyPairFromSerializedPubKey(authResp.MasterRunnerPubKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to KeyPairFromSerializablePubKey")
	}

	return client, nil
}

// SendTask sends a task to be run
func (c *Client) SendTask(body []byte, kind string, meta *model.TaskMeta) (string, error) {
	taskKeyPair, err := simplcrypto.GenerateNewKeyPair()
	if err != nil {
		return "", errors.Wrap(err, "failed to GenerateNewKeyPair")
	}

	taskKey, err := simplcrypto.GenerateSymKey()
	if err != nil {
		return "", errors.Wrap(err, "failed to GenerateSymKey")
	}

	clientEncTaskKey, err := taskKeyPair.Encrypt(taskKey.JSON())
	if err != nil {
		return "", errors.Wrap(err, "failed to Encrypt clientEncTaskKey")
	}

	masterEncTaskKeyJSON, err := c.masterRunnerPubKey.Encrypt(taskKey.JSON())
	if err != nil {
		return "", errors.Wrap(err, "failed to Encrypt masterEncTaskKey")
	}

	task := &model.Task{}

	if meta != nil {
		task.Meta = meta
	} else {
		task.Meta = &model.TaskMeta{}
	}

	encBody, err := taskKey.Encrypt(body)
	if err != nil {
		return "", errors.Wrap(err, "failed to Encrypt task body")
	}

	task.Meta.MasterEncTaskKey = masterEncTaskKeyJSON
	task.Meta.ClientEncTaskKey = clientEncTaskKey
	task.EncBody = encBody

	resp, err := c.client.Queue(context.Background(), task)
	if err != nil {
		return "", errors.Wrap(err, "failed to Queue")
	}

	c.keyLock.Lock()
	c.taskKeyPairs[resp.UUID] = taskKeyPair // TODO: persist this in real/shared storage
	c.taskKeys[resp.UUID] = taskKey
	c.keyLock.Unlock()

	return resp.UUID, nil
}

// GetTaskResult gets a task's result
func (c *Client) GetTaskResult(uuid string) ([]byte, error) {
	stream, err := c.client.CheckTask(context.Background(), &service.CheckTaskRequest{UUID: uuid})
	if err != nil {
		return nil, errors.Wrap(err, "failed to CheckTask")
	}

	for {
		resp, err := stream.Recv()
		if err != nil {
			return nil, errors.Wrap(err, "failed to Recv")
		}

		log.LogInfo(fmt.Sprintf("task %s status %s", uuid, resp.Status))

		if resp.Status == model.TaskStatusCompleted {
			result, err := c.decryptResult(uuid, resp)
			if err != nil {
				return nil, errors.Wrap(err, "failed to decryptResult for complete task")
			}

			return result, nil
		} else if resp.Status == model.TaskStatusFailed {
			// do nothing for now
		}

		<-time.After(time.Second)
	}
}

func (c *Client) decryptResult(taskUUID string, taskResponse *service.CheckTaskResponse) ([]byte, error) {
	c.keyLock.Lock()
	taskKey, ok := c.taskKeys[taskUUID]
	if !ok {
		// if this client didn't create the task, fetch the task keypair
		// from storage and decrypt the task key from metadata
		// TODO: add... well, real storage
		taskKeyPair, ok := c.taskKeyPairs[taskUUID]
		if !ok {
			return nil, errors.New(fmt.Sprintf("unable to find task %s key", taskUUID))
		}

		taskKeyJSON, err := taskKeyPair.Decrypt(taskResponse.EncTaskKey)
		if err != nil {
			return nil, errors.Wrap(err, "failed to Decrypt task key JSON")
		}

		taskKey, err = simplcrypto.SymKeyFromJSON(taskKeyJSON)
		if err != nil {
			return nil, errors.Wrap(err, "failed to SymKeyFromJSON")
		}
	}
	c.keyLock.Unlock()

	decResult, err := taskKey.Decrypt(taskResponse.Result.EncResult)
	if err != nil {
		return nil, errors.Wrap(err, "failed to Decrypt result")
	}

	return decResult, nil
}
