package beacon

import (
	"github.com/sirupsen/logrus"
	"os"
)

var log = logrus.New()

func init() {
	log.Out = os.Stdout
	log.Printf("Finished initializing beacon logging for linux")
}
