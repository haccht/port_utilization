package main

import (
	"bytes"
	"flag"
	"fmt"
	"math/big"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	hu "github.com/dustin/go-humanize"
	ui "github.com/gizak/termui"
	"github.com/k-sone/snmpgo"
)

type ifStats struct {
	ifHCInOctets  *big.Int
	ifInDiscards  *big.Int
	ifInErrors    *big.Int
	ifHCOutOctets *big.Int
	ifOutDiscards *big.Int
	ifOutErrors   *big.Int
}

type Dashboard struct {
	snmp *snmpgo.SNMP

	ifIndex int
	ifSpeed *big.Int
	ifStats *ifStats

	Par1    *ui.Par
	Par2    *ui.Par
	Par3    *ui.Par
	ChartRx *ui.LineChart
	ChartTx *ui.LineChart
}

func NewDashboard(snmp *snmpgo.SNMP, name string) (*Dashboard, error) {
	b := &Dashboard{
		snmp: snmp,

		Par1:    ui.NewPar(""),
		Par2:    ui.NewPar(""),
		Par3:    ui.NewPar(""),
		ChartRx: ui.NewLineChart(),
		ChartTx: ui.NewLineChart(),
	}

	b.Par1.BorderLabel = "Interface"
	b.Par1.TextFgColor = ui.ColorWhite
	b.Par1.Height = 4
	b.Par1.Width = 81

	b.Par2.BorderLabel = "Raw Data"
	b.Par2.TextFgColor = ui.ColorWhite
	b.Par2.Height = 5
	b.Par2.Width = 81
	b.Par2.Y = 4

	b.Par3.Border = false
	b.Par3.Height = 1
	b.Par3.Width = 29
	b.Par3.X = 52
	b.Par3.Y = 19

	b.ChartRx.BorderLabel = "Rx Utilization (%)"
	b.ChartRx.Data["rate"] = make([]float64, 0, 120)
	b.ChartRx.LineColor["rate"] = ui.ColorYellow
	b.ChartRx.Width = 40
	b.ChartRx.Height = 10
	b.ChartRx.Y = 9
	b.ChartRx.YFloor = 0
	b.ChartRx.YCeil = 100

	b.ChartTx.BorderLabel = "Tx Utilization (%)"
	b.ChartTx.Data["rate"] = make([]float64, 0, 120)
	b.ChartTx.LineColor["rate"] = ui.ColorYellow
	b.ChartTx.Width = 40
	b.ChartTx.Height = 10
	b.ChartTx.X = 41
	b.ChartTx.Y = 9
	b.ChartTx.YFloor = 0
	b.ChartTx.YCeil = 100

	ifName, ifIndex, err := b.parseIfName(name)
	if err != nil {
		return nil, err
	}

	oid_sysName := snmpgo.MustNewOid("1.3.6.1.2.1.1.5.0")
	oid_ifAlias := snmpgo.MustNewOid("1.3.6.1.2.1.31.1.1.1.18." + strconv.Itoa(ifIndex))
	oid_ifHighSpeed := snmpgo.MustNewOid("1.3.6.1.2.1.31.1.1.1.15." + strconv.Itoa(ifIndex))

	pdu, err := b.snmp.GetRequest(snmpgo.Oids{oid_sysName, oid_ifAlias, oid_ifHighSpeed})
	if err != nil {
		return nil, err
	}
	if pdu.ErrorStatus() != snmpgo.NoError {
		return nil, fmt.Errorf("Failed - %s(%d)", pdu.ErrorStatus(), pdu.ErrorIndex())
	}

	sysName := pdu.VarBinds().MatchOid(oid_sysName).Variable.String()
	ifAlias := pdu.VarBinds().MatchOid(oid_ifAlias).Variable.String()
	ifHighSpeed, _ := pdu.VarBinds().MatchOid(oid_ifHighSpeed).Variable.BigInt()

	buffer := bytes.NewBuffer(nil)
	buffer.WriteString("[sysName:](fg-bold) %-31s [ifName:](fg-bold)  %s\n")
	buffer.WriteString("[ifAlias:](fg-bold) %-31s [ifSpeed:](fg-bold) %s Mbps")

	b.Par1.Text = fmt.Sprintf(buffer.String(),
		ui.TrimStrIfAppropriate(sysName, 31),
		ifName,
		ui.TrimStrIfAppropriate(ifAlias, 31),
		hu.Comma(ifHighSpeed.Int64()),
	)

	b.ifIndex = ifIndex
	b.ifSpeed = ifHighSpeed

	return b, nil
}

func (b *Dashboard) parseIfName(name string) (string, int, error) {
	var ifName string
	var ifIndex int

	r := regexp.MustCompile(`^\.\d+$`)
	if r.MatchString(name) {
		oid_ifName := snmpgo.MustNewOid("1.3.6.1.2.1.31.1.1.1.1" + name)

		pdu, err := b.snmp.GetRequest(snmpgo.Oids{oid_ifName})
		if err != nil {
			return ifName, ifIndex, err
		}
		if pdu.ErrorStatus() != snmpgo.NoError {
			err := fmt.Errorf("Failed - %s(%d)", pdu.ErrorStatus(), pdu.ErrorIndex())
			return ifName, ifIndex, err
		}

		varBind := pdu.VarBinds().MatchOid(oid_ifName)

		ifName = varBind.Variable.String()
		ifIndex, _ = strconv.Atoi(name[1:])

		return ifName, ifIndex, nil
	} else {
		oid_ifName := snmpgo.MustNewOid("1.3.6.1.2.1.31.1.1.1.1")

		pdu, err := b.snmp.GetBulkWalk(snmpgo.Oids{oid_ifName}, 0, 10)
		if err != nil {
			return ifName, ifIndex, err
		}
		if pdu.ErrorStatus() != snmpgo.NoError {
			err := fmt.Errorf("Failed - %s(%d)", pdu.ErrorStatus(), pdu.ErrorIndex())
			return ifName, ifIndex, err
		}

		for _, varBind := range pdu.VarBinds().MatchBaseOids(oid_ifName) {
			if strings.Index(strings.ToUpper(varBind.Variable.String()), strings.ToUpper(name)) != -1 {
				ifName = varBind.Variable.String()
				ifIndex = varBind.Oid.Value[len(oid_ifName.Value)]
				return ifName, ifIndex, nil
			}
		}

		return ifName, ifIndex, fmt.Errorf("interface '%s' not fould", name)
	}
}

func (b *Dashboard) UpdateData(t int) error {
	oid_ifHCInOctets := snmpgo.MustNewOid("1.3.6.1.2.1.31.1.1.1.6." + strconv.Itoa(b.ifIndex))
	oid_ifInDiscards := snmpgo.MustNewOid("1.3.6.1.2.1.2.2.1.13." + strconv.Itoa(b.ifIndex))
	oid_ifInErrors := snmpgo.MustNewOid("1.3.6.1.2.1.2.2.1.14." + strconv.Itoa(b.ifIndex))
	oid_ifHCOutOctets := snmpgo.MustNewOid("1.3.6.1.2.1.31.1.1.1.10." + strconv.Itoa(b.ifIndex))
	oid_ifOutDiscards := snmpgo.MustNewOid("1.3.6.1.2.1.2.2.1.19." + strconv.Itoa(b.ifIndex))
	oid_ifOutErrors := snmpgo.MustNewOid("1.3.6.1.2.1.2.2.1.20." + strconv.Itoa(b.ifIndex))

	pdu, err := b.snmp.GetRequest(snmpgo.Oids{
		oid_ifHCInOctets,
		oid_ifInDiscards,
		oid_ifInErrors,
		oid_ifHCOutOctets,
		oid_ifOutDiscards,
		oid_ifOutErrors,
	})
	if err != nil {
		return err
	}
	if pdu.ErrorStatus() != snmpgo.NoError {
		return fmt.Errorf("Failed - %s(%d)", pdu.ErrorStatus(), pdu.ErrorIndex())
	}

	stats := &ifStats{}
	stats.ifHCInOctets, _ = pdu.VarBinds().MatchOid(oid_ifHCInOctets).Variable.BigInt()
	stats.ifInDiscards, _ = pdu.VarBinds().MatchOid(oid_ifInDiscards).Variable.BigInt()
	stats.ifInErrors, _ = pdu.VarBinds().MatchOid(oid_ifInErrors).Variable.BigInt()
	stats.ifHCOutOctets, _ = pdu.VarBinds().MatchOid(oid_ifHCOutOctets).Variable.BigInt()
	stats.ifOutDiscards, _ = pdu.VarBinds().MatchOid(oid_ifOutDiscards).Variable.BigInt()
	stats.ifOutErrors, _ = pdu.VarBinds().MatchOid(oid_ifOutErrors).Variable.BigInt()

	delta := &ifStats{}
	delta.ifHCInOctets = big.NewInt(0)
	delta.ifInDiscards = big.NewInt(0)
	delta.ifInErrors = big.NewInt(0)
	delta.ifHCOutOctets = big.NewInt(0)
	delta.ifOutDiscards = big.NewInt(0)
	delta.ifOutErrors = big.NewInt(0)

	if b.ifStats != nil {
		delta.ifHCInOctets.Sub(stats.ifHCInOctets, b.ifStats.ifHCInOctets)
		delta.ifInDiscards.Sub(stats.ifInDiscards, b.ifStats.ifInDiscards)
		delta.ifInErrors.Sub(stats.ifInErrors, b.ifStats.ifInErrors)
		delta.ifHCOutOctets.Sub(stats.ifHCOutOctets, b.ifStats.ifHCOutOctets)
		delta.ifOutDiscards.Sub(stats.ifOutDiscards, b.ifStats.ifOutDiscards)
		delta.ifOutErrors.Sub(stats.ifOutErrors, b.ifStats.ifOutErrors)
	}

	b.ifStats = stats

	buffer := bytes.NewBuffer(nil)
	buffer.WriteString("[ifHCInOctets:](fg-bold)  %21s     [ifHCOutOctets:](fg-bold) %21s\n")
	buffer.WriteString("[ifInDiscards:](fg-bold)  %21s     [ifOutDiscards:](fg-bold) %21s\n")
	buffer.WriteString("[ifInErrors:](fg-bold)    %21s     [ifOutErrors:](fg-bold)   %21s")

	b.Par2.Text = fmt.Sprintf(buffer.String(),
		hu.Comma(delta.ifHCInOctets.Int64()),
		hu.Comma(delta.ifHCOutOctets.Int64()),
		hu.Comma(delta.ifInDiscards.Int64()),
		hu.Comma(delta.ifOutDiscards.Int64()),
		hu.Comma(delta.ifInErrors.Int64()),
		hu.Comma(delta.ifOutErrors.Int64()),
	)

	rxRate := (float64(delta.ifHCInOctets.Int64()) * 8 * 100) / (float64(b.ifSpeed.Int64()) * float64(t) * 1000000)
	txRate := (float64(delta.ifHCOutOctets.Int64()) * 8 * 100) / (float64(b.ifSpeed.Int64()) * float64(t) * 1000000)
	b.ChartRx.Data["rate"] = append(b.ChartRx.Data["rate"], rxRate)
	b.ChartTx.Data["rate"] = append(b.ChartTx.Data["rate"], txRate)

	return nil
}

func (b *Dashboard) UpdateTime(t int) {
	b.Par3.Text = fmt.Sprintf(
		"%11s (press q to quit)",
		time.Duration(t)*time.Second,
	)
}

func main() {
	var interval int
	var version, community string

	flag.IntVar(&interval, "t", 1, "Request interval")
	flag.StringVar(&version, "v", "2c", "SNMP version (2c|3)")
	flag.StringVar(&community, "c", "", "SNMP community")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS] agent ifName\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "OPTIONS:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if community == "" || flag.NArg() != 2 {
		flag.Usage()
		os.Exit(1)
	}

	args := flag.Args()
	snmpArgs := snmpgo.SNMPArguments{
		Address:   args[0] + ":161",
		Community: community,
	}

	switch version {
	case "2c":
		snmpArgs.Version = snmpgo.V2c
	case "3":
		snmpArgs.Version = snmpgo.V3
	default:
		flag.Usage()
		os.Exit(1)
	}

	snmp, err := snmpgo.NewSNMP(snmpArgs)

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if err := snmp.Open(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer snmp.Close()

	if err := ui.Init(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer ui.Close()

	b, err := NewDashboard(snmp, args[1])
	if err != nil {
		ui.Close()
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	b.UpdateData(interval)
	ui.Render(b.Par1, b.Par2, b.Par3, b.ChartRx, b.ChartTx)

	ui.Handle("/timer/1s", func(e ui.Event) {
		t := e.Data.(ui.EvtTimer)
		c := int(t.Count)
		if c%interval == 0 {
			b.UpdateData(interval)
			b.UpdateTime(c)
			ui.Render(b.Par2, b.Par3, b.ChartRx, b.ChartTx)
		} else {
			b.UpdateTime(c)
			ui.Render(b.Par3)
		}
	})

	ui.Handle("/sys/kbd/q", func(ui.Event) {
		ui.StopLoop()
	})

	ui.Loop()
}
