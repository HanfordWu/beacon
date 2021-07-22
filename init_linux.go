package beacon

import (
	"os"

	"github.com/sirupsen/logrus"
)

var log = logrus.New()

func init() {
	log.Out = os.Stdout
	log.Printf("Finished initializing beacon logging for linux")
}
