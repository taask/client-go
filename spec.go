package taask

import (
	"encoding/json"

	"github.com/cohix/simplcrypto"
	"github.com/pkg/errors"
	"github.com/taask/taask-server/model"
)

// TaskTypeTask and others are types of tasks
const (
	TaskTypeImmediate = "io.taask.immediate"
	TaskTypeDeferred  = "io.taask.deferred" // not yet supported
	TaskTypeRepeated  = "io.taask.repeated" // not yet supported

	TaskKindK8s = "io.taask.k8s"
)

// Spec defines the metadata wrapper for a task spec
type Spec struct {
	Version int
	Type    string
	Spec    Task
}

// Task is a user-facing variant of taask/taask-server/model/Task
type Task struct {
	Meta TaskMeta
	Kind string
	Body map[string]interface{}
}

// TaskMeta is a user-facing variant of taask/taask-server/model/TaskMeta
type TaskMeta struct {
	Annotations    []string `yaml:"Annotations,omitempty"`
	TimeoutSeconds int32    `yaml:"TimeoutSeconds,omitempty"`
}

// ToModel converts a spec.Task to a model.Task by encrypting it and setting the appropriate fields
func (t *Task) ToModel(taskKey *simplcrypto.SymKey, masterRunnerKey *simplcrypto.KeyPair, groupKey *simplcrypto.SymKey) (*model.Task, error) {
	bodyJSON, err := json.Marshal(t.Body)
	if err != nil {
		return nil, errors.Wrap(err, "failed to Marshal body")
	}

	encBody, err := taskKey.Encrypt(bodyJSON)
	if err != nil {
		return nil, errors.Wrap(err, "failed to Encrypt body JSON")
	}

	masterEncKey, err := masterRunnerKey.Encrypt(taskKey.JSON())
	if err != nil {
		return nil, errors.Wrap(err, "failed to Encrypt task key for runners")
	}

	clientEncKey, err := groupKey.Encrypt(taskKey.JSON())
	if err != nil {
		return nil, errors.Wrap(err, "failed to Encrypt task key for client")
	}

	task := &model.Task{
		Meta: &model.TaskMeta{
			Annotations:      t.Meta.Annotations,
			TimeoutSeconds:   t.Meta.TimeoutSeconds,
			MasterEncTaskKey: masterEncKey,
			ClientEncTaskKey: clientEncKey,
		},
		Kind:    t.Kind,
		EncBody: encBody,
	}

	if task.Kind == "" {
		task.Kind = TaskKindK8s
	}

	return task, nil
}
