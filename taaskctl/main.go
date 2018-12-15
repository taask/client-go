package main

import (
	"encoding/json"
	"fmt"
	"math/rand"
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
	client, err := taask.NewClient("localhost", "30688")
	if err != nil {
		log.LogError(errors.Wrap(err, "failed to NewClient"))
		os.Exit(1)
	}

	numTasks := 1000
	resultChan := make(chan answer)

	for i := 0; i < numTasks; i++ {
		go func(resultChan chan answer) {
			taskBody := addition{
				First:  rand.Intn(50),
				Second: rand.Intn(100),
			}

			taskBodyJSON, err := json.Marshal(taskBody)
			if err != nil {
				log.LogError(errors.Wrap(err, "failed to Marshal"))
				os.Exit(1)
			}

			task := &model.Task{
				Meta: &model.TaskMeta{
					TimeoutSeconds: 60,
				},
				Kind: "io.taask.k8s",
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

			resultChan <- taskAnswer
		}(resultChan)
	}

	completed := 0
	log.LogInfo("waiting for answers")

	for {
		answer := <-resultChan
		log.LogInfo(fmt.Sprintf("task answer: %d", answer.Answer))

		completed++

		log.LogInfo(fmt.Sprintf("%d/%d completed", completed, numTasks))

		if completed == numTasks {
			break
		}
	}
}
