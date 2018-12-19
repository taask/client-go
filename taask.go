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

// type StatusUpdateFunc func() string

// NewClient creates a Client
func NewClient(addr, port string) (*Client, error) {
	conn, err := grpc.Dial(fmt.Sprintf("%s:%s", addr, port), grpc.WithInsecure())
	if err != nil {
		return nil, errors.Wrap(err, "failed to Dial")
	}

	tClient := service.NewTaskServiceClient(conn)

	authResp, err := tClient.AuthClient(context.Background(), &service.AuthClientRequest{})
	if err != nil {
		return nil, errors.Wrap(err, "failed to AuthClient")
	}

	masterRunnerPubKey, err := simplcrypto.KeyPairFromSerializedPubKey(authResp.MasterRunnerPubKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to KeyPairFromSerializablePubKey")
	}

	client := &Client{
		client:             tClient,
		masterRunnerPubKey: masterRunnerPubKey,
		taskKeyPairs:       make(map[string]*simplcrypto.KeyPair),
		taskKeys:           make(map[string]*simplcrypto.SymKey),
		keyLock:            &sync.Mutex{},
	}

	return client, nil
}

// SendTask sends a task to be run
func (c *Client) SendTask(body map[string]interface{}, kind string, meta TaskMeta) (string, error) {
	task := Task{
		Meta: meta,
		Kind: kind,
		Body: body,
	}

	return c.SendSpecTask(task)
}

// SendSpecTask sends a task from a spec task
func (c *Client) SendSpecTask(spec Task) (string, error) {
	if spec.Body == nil {
		return "", errors.New("task body is nil")
	}

	taskKeyPair, err := simplcrypto.GenerateNewKeyPair()
	if err != nil {
		return "", errors.Wrap(err, "failed to GenerateNewKeyPair")
	}

	taskKey, err := simplcrypto.GenerateSymKey()
	if err != nil {
		return "", errors.Wrap(err, "failed to GenerateSymKey")
	}

	task, err := spec.ToModel(taskKey, c.masterRunnerPubKey, taskKeyPair)
	if err != nil {
		return "", errors.Wrap(err, "failed to ToModel")
	}

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

// StreamTaskResult gets a task's result
func (c *Client) StreamTaskResult(uuid string) ([]byte, error) {
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

// GetTaskStatus gets a task's current status
func (c *Client) GetTaskStatus(uuid string) (string, error) {
	stream, err := c.client.CheckTask(context.Background(), &service.CheckTaskRequest{UUID: uuid})
	if err != nil {
		return "", errors.Wrap(err, "failed to CheckTask")
	}

	resp, err := stream.Recv()
	if err != nil {
		return "", errors.Wrap(err, "failed to Recv")
	}

	log.LogInfo(fmt.Sprintf("task %s status %s", uuid, resp.Status))

	return resp.Status, nil
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
