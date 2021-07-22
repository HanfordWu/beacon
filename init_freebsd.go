package beacon

import (
	"log/syslog"

	"github.com/sirupsen/logrus"
	lSyslog "github.com/sirupsen/logrus/hooks/syslog"
)

var log = logrus.New()

func init() {
	// Send all logs of severity info and higher to local syslog daemon
	var hook, err = lSyslog.NewSyslogHook("", "", syslog.LOG_INFO, "")
	if err == nil {
		log.Printf("Adding syslog hook")
		log.Hooks.Add(hook)
	} else {
		log.Printf("Error getting syslog hook: %s", err)
	}
	log.Printf("Finished initializing beacon logging for freebsd")
}
