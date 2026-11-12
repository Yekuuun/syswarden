package pipeline

import (
	"io"
	"log"
)

func captureLog(w io.Writer) func() {
	prevOut, prevFlags := log.Writer(), log.Flags()
	log.SetOutput(w)
	log.SetFlags(0)
	return func() {
		log.SetOutput(prevOut)
		log.SetFlags(prevFlags)
	}
}
