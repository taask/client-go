package main

import (
	"encoding/json"
	"fmt"
	"os"

	log "github.com/cohix/simplog"
	"github.com/pkg/errors"
	taask "github.com/taask/client-golang"
	"github.com/taask/taask-server/model"
)

type addition struct {
	First  int
	Second int
}

type answer struct {
	Answer int
}

func main() {
	client, err := taask.NewClient("localhost", "3688")
	if err != nil {
		log.LogError(errors.Wrap(err, "failed to NewClient"))
		os.Exit(1)
	}

	taskBody := addition{
		First:  5,
		Second: 12,
	}

	taskBodyJSON, err := json.Marshal(taskBody)
	if err != nil {
		log.LogError(errors.Wrap(err, "failed to Marshal"))
		os.Exit(1)
	}

	task := &model.Task{
		Kind: "com.taask.dummy",
		Body: taskBodyJSON,
	}

	uuid, err := client.SendTask(task)
	if err != nil {
		log.LogError(errors.Wrap(err, "failed to SendTask"))
		os.Exit(1)
	}

	resultJSON, err := client.GetTaskResult(uuid)
	if err != nil {
		log.LogError(errors.Wrap(err, "failed to GetTaskResult"))
		os.Exit(1)
	}

	var taskAnswer answer
	if err := json.Unmarshal(resultJSON, &taskAnswer); err != nil {
		log.LogError(errors.Wrap(err, "failed to Unmarshal"))
	}

	log.LogInfo(fmt.Sprintf("task answer: %d", taskAnswer.Answer))
}
