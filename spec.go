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
	TaskTypeScheduled = "io.taask.scheduled" // not yet supported
	TaskTypeRepeated  = "io.taask.repeated"  // not yet supported
)

// Spec defines the metadata wrapper for a task spec
type Spec struct {
	Version int    `yaml:"Version"`
	Type    string `yaml:"Type"`
	Spec    Task   `yaml:"Spec"`
}

// Task is a user-facing variant of taask/taask-server/model/Task
type Task struct {
	Meta TaskMeta    `yaml:"Meta"`
	Kind string      `yaml:"Kind,omitempty"` // defaults to io.taask.k8s
	Body interface{} `yaml:"Body"`
}

// TaskMeta is a user-facing variant of taask/taask-server/model/TaskMeta
type TaskMeta struct {
	Annotations    []string `yaml:"Annotations,omitempty"`
	TimeoutSeconds int32    `yaml:"TimeoutSeconds,omitempty"`
}

// ToModel converts a spec.Task to a model.Task by encrypting it and setting the appropriate fields
func (t *Task) ToModel(taskKey *simplcrypto.SymKey, masterRunnerKey, taskKeypair *simplcrypto.KeyPair) (*model.Task, error) {
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

	clientEncKey, err := taskKeypair.Encrypt(taskKey.JSON())
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

	return task, nil
}
