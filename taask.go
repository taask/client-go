package taask

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/cohix/simplcrypto"

	"github.com/pkg/errors"
	"github.com/taask/taask-server/model"
	"github.com/taask/taask-server/service"
	"google.golang.org/grpc"
)

// Client describes a taask client
type Client struct {
	client    service.TaskServiceClient
	localAuth *LocalAuthConfig
	taskKeys  map[string]*simplcrypto.SymKey
	keyLock   *sync.Mutex
}

// type StatusUpdateFunc func() string

// NewClient creates a Client
func NewClient(addr, port string, localAuth *LocalAuthConfig) (*Client, error) {
	conn, err := grpc.Dial(fmt.Sprintf("%s:%s", addr, port), grpc.WithInsecure())
	if err != nil {
		return nil, errors.Wrap(err, "failed to Dial")
	}

	tClient := service.NewTaskServiceClient(conn)

	if err := localAuth.Authenticate(tClient); err != nil {
		return nil, errors.Wrap(err, "failed to Authenticate")
	}

	client := &Client{
		client:    tClient,
		localAuth: localAuth,
		taskKeys:  make(map[string]*simplcrypto.SymKey),
		keyLock:   &sync.Mutex{},
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

	groupKey, err := c.localAuth.GroupKey()
	if err != nil {
		return "", errors.Wrap(err, "failed to GroupKey")
	}

	taskKey, err := simplcrypto.GenerateSymKey()
	if err != nil {
		return "", errors.Wrap(err, "failed to GenerateSymKey")
	}

	task, err := spec.ToModel(taskKey, c.localAuth.ActiveSession.MasterRunnerPubKey, groupKey)
	if err != nil {
		return "", errors.Wrap(err, "failed to ToModel")
	}

	req := &service.QueueTaskRequest{
		Task:    task,
		Session: c.localAuth.ActiveSession.Session,
	}

	resp, err := c.client.Queue(context.Background(), req)
	if err != nil {
		return "", errors.Wrap(err, "failed to Queue")
	}

	c.keyLock.Lock()
	c.taskKeys[resp.UUID] = taskKey
	c.keyLock.Unlock()

	return resp.UUID, nil
}

// StreamTaskResult gets a task's result
func (c *Client) StreamTaskResult(uuid string) ([]byte, error) {
	req := &service.CheckTaskRequest{
		UUID:    uuid,
		Session: c.localAuth.ActiveSession.Session,
	}

	stream, err := c.client.CheckTask(context.Background(), req)
	if err != nil {
		return nil, errors.Wrap(err, "failed to CheckTask")
	}

	for {
		resp, err := stream.Recv()
		if err != nil {
			return nil, errors.Wrap(err, "failed to Recv")
		}

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
	req := &service.CheckTaskRequest{
		UUID:    uuid,
		Session: c.localAuth.ActiveSession.Session,
	}

	stream, err := c.client.CheckTask(context.Background(), req)
	if err != nil {
		return "", errors.Wrap(err, "failed to CheckTask")
	}

	resp, err := stream.Recv()
	if err != nil {
		return "", errors.Wrap(err, "failed to Recv")
	}

	return resp.Status, nil
}

func (c *Client) decryptResult(taskUUID string, taskResponse *service.CheckTaskResponse) ([]byte, error) {
	c.keyLock.Lock()
	taskKey, ok := c.taskKeys[taskUUID]
	if !ok {
		groupKey, err := c.localAuth.GroupKey()
		if err != nil {
			return nil, errors.Wrap(err, "failed to GroupKey")
		}

		// TODO: figure out how to remove this hack... it's not really a problem, but it's messy.
		groupKey.KID = taskResponse.EncTaskKey.KID

		taskKeyJSON, err := groupKey.Decrypt(taskResponse.EncTaskKey)
		if err != nil {
			return nil, errors.Wrap(err, "failed to Decrypt task key JSON")
		}

		taskKey, err = simplcrypto.SymKeyFromJSON(taskKeyJSON)
		if err != nil {
			return nil, errors.Wrap(err, "failed to SymKeyFromJSON")
		}

		c.taskKeys[taskUUID] = taskKey // cache it
	}
	c.keyLock.Unlock()

	decResult, err := taskKey.Decrypt(taskResponse.Result.EncResult)
	if err != nil {
		return nil, errors.Wrap(err, "failed to Decrypt result")
	}

	return decResult, nil
}
