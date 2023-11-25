package main

import (
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"os"
	"os/signal"
	"syscall"
	"txRay/tracer"
)

var (
	device     string
	targetPort string
	targetAddr string
)

func init() {
	rootCmd.Flags().StringVarP(&device, "interface", "i", "", "target interface(e.g. eth0)")
	rootCmd.Flags().StringVar(&targetAddr, "addr", "",
		"only keep packets the contains specified IP address and filter others out")
	rootCmd.Flags().StringVar(&targetPort, "port", "", "specify port and filter others out")
	rootCmd.MarkFlagRequired("interface")
}

var rootCmd = &cobra.Command{
	Use:   "txray",
	Short: "txray is a tool used for monitoring traffic",
	RunE: func(cmd *cobra.Command, args []string) error {
		conf := tracer.Config{
			Interface: device,
			Port:      targetPort,
			Addr:      targetAddr,
		}
		prog := tracer.NewTracer(&conf)
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL)
		go func() {
			select {
			case sig := <-sigs:
				prog.Stop()
				log.Infof("txRay exits by SIGNAL:%v", sig)
			}
			os.Exit(0)
		}()
		prog.Start()
		select {}
	},
}
