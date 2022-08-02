package main

import (
	"log"
	"os"
	"text/template"
)

// ProfileHeader contain sAppArmor Profile/SubProfile header config
type ProfileHeader struct {
	File, Network, Capabilities bool
}

// RuleConfig contains details for individual apparmor rules
type RuleConfig struct {
	Value                                     string
	Dir, Recursive, Deny, ReadOnly, OwnerOnly bool
}

// Rules contains configuration for the AppArmor Profile/SubProfile Body
type Rules struct {
	FilePaths         []RuleConfig
	ProcessPaths      []RuleConfig
	NetworkRules      []RuleConfig
	CapabilitiesRules []RuleConfig
}

// FromSourceConfig has details for individual from source subprofiles
type FromSourceConfig struct {
	Fusion bool
	ProfileHeader
	Rules
}

// Profile header has all the details for a new AppArmor profile
type Profile struct {
	Name string
	ProfileHeader
	Rules
	FromSource map[string]FromSourceConfig
}

func main() {

	const profiletmpl = `
## == Managed by KubeArmor == ##

#include <tunables/global>

profile {{.Name}} flags=(attach_disconnected,mediate_deleted) {

  ## == PRE START == ##

  #include <abstractions/base>

{{if .File}}  file,{{end}}{{if .Network}}
  network,{{end}}{{if .Capabilities}}
  capability,{{end}}

  ## == PRE END == ##

  ## == POLICY START == ##
{{range .FilePaths}}{{$value := .Value}}{{$suffix := ""}}{{if and .Dir .Recursive}}{{$suffix = "**"}}{{else if .Dir}}{{$suffix = "*"}}{{end}}{{if .Deny}}{{if and .ReadOnly .OwnerOnly}}
  deny owner {{$value}}{{$suffix}} w,
  deny other {{$value}}{{$suffix}} rw,{{else if .OwnerOnly}}
  owner {{$value}}{{$suffix}} rw,
  deny other {{$value}}{{$suffix}} rw,{{else if .ReadOnly}}
  deny {{$value}}{{$suffix}} w,{{else}}
  deny {{$value}}{{$suffix}} rw,{{end}}{{else}}{{if and .ReadOnly .OwnerOnly}}
  owner {{$value}}{{$suffix}} r,{{else if .OwnerOnly}}
  owner {{$value}}{{$suffix}} rw,{{else if .ReadOnly}}
  {{$value}}{{$suffix}} r,{{else}}
  {{$value}}{{$suffix}} rw,
{{end}}{{end}}{{end}}
{{range .ProcessPaths}}{{$value := .Value}}{{$suffix := ""}}{{if and .Dir .Recursive}}{{$suffix = "**"}}{{else if .Dir}}{{$suffix = "*"}}{{end}}{{if .Deny}}{{if .OwnerOnly}}
  owner {{$value}}{{$suffix}} ix,
  deny other {{$value}}{{$suffix}} x,{{else}}
  deny {{$value}}{{$suffix}} x,{{end}}{{else}}{{if .OwnerOnly}}
  owner {{$value}}{{$suffix}} ix,{{else}}
  {{$value}}{{$suffix}} ix,{{end}}{{end}}{{end}}
{{range .NetworkRules}}{{$value := .Value}}{{if .Deny}}
  deny network {{$value}},{{else}}
  network {{$value}},{{end}}{{end}}
{{range .CapabilitiesRules}}{{$value := .Value}}{{if .Deny}}
  deny capability {{$value}},{{else}}
  capability {{$value}},
{{end}}{{end}}

{{ range $source, $value := $.FromSource }}{{if $value.Fusion}}
  {{$source}}  cix,{{else}}
  {{$source}}  cx,{{end}}
  profile {{$source}} {

    {{$source}} rix,
    ## == PRE START == ##

    #include <abstractions/base>
  
{{if .File}}    file,{{end}}{{if .Network}}
    network,{{end}}{{if .Capabilities}}
    capability,{{end}}
  
    ## == PRE END == ##
  
    ## == POLICY START == ##
  {{range .FilePaths}}{{$value := .Value}}{{$suffix := ""}}{{if and .Dir .Recursive}}{{$suffix = "**"}}{{else if .Dir}}{{$suffix = "*"}}{{end}}{{if .Deny}}{{if and .ReadOnly .OwnerOnly}}
    deny owner {{$value}}{{$suffix}} w,
    deny other {{$value}}{{$suffix}} rw,{{else if .OwnerOnly}}
    owner {{$value}}{{$suffix}} rw,
    deny other {{$value}}{{$suffix}} rw,{{else if .ReadOnly}}
    deny {{$value}}{{$suffix}} w,{{else}}
    deny {{$value}}{{$suffix}} rw,{{end}}{{else}}{{if and .ReadOnly .OwnerOnly}}
    owner {{$value}}{{$suffix}} r,{{else if .OwnerOnly}}
    owner {{$value}}{{$suffix}} rw,{{else if .ReadOnly}}
    {{$value}}{{$suffix}} r,{{else}}
    {{$value}}{{$suffix}} rw,
  {{end}}{{end}}{{end}}
  {{range .ProcessPaths}}{{$value := .Value}}{{$suffix := ""}}{{if and .Dir .Recursive}}{{$suffix = "**"}}{{else if .Dir}}{{$suffix = "*"}}{{end}}{{if .Deny}}{{if .OwnerOnly}}
    owner {{$value}}{{$suffix}} ix,
    deny other {{$value}}{{$suffix}} x,{{else}}
    deny {{$value}}{{$suffix}} x,{{end}}{{else}}{{if .OwnerOnly}}
    owner {{$value}}{{$suffix}} ix,{{else}}
    {{$value}}{{$suffix}} ix,{{end}}{{end}}{{end}}
  {{range .NetworkRules}}{{$value := .Value}}{{if .Deny}}
    deny network {{$value}},{{else}}
    network {{$value}},{{end}}{{end}}
  {{range .CapabilitiesRules}}{{$value := .Value}}{{if .Deny}}
    deny capability {{$value}},{{else}}
    capability {{$value}},
  {{end}}{{end}}
    ## == POLICY END == ##
  
    ## == POST START == ##
  
    /lib/x86_64-linux-gnu/{*,**} rm,
    
    deny @{PROC}/{*,**^[0-9*],sys/kernel/shm*} wkx,
    deny @{PROC}/sysrq-trigger rwklx,
    deny @{PROC}/mem rwklx,
    deny @{PROC}/kmem rwklx,
    deny @{PROC}/kcore rwklx,
    
    deny mount,
    
    deny /sys/[^f]*/** wklx,
    deny /sys/f[^s]*/** wklx,
    deny /sys/fs/[^c]*/** wklx,
    deny /sys/fs/c[^g]*/** wklx,
    deny /sys/fs/cg[^r]*/** wklx,
    deny /sys/firmware/efi/efivars/** rwklx,
    deny /sys/kernel/security/** rwklx,
  
    ## == POST END == ##

  }
{{ end }}


  ## == POLICY END == ##

  ## == POST START == ##

  /lib/x86_64-linux-gnu/{*,**} rm,
  
  deny @{PROC}/{*,**^[0-9*],sys/kernel/shm*} wkx,
  deny @{PROC}/sysrq-trigger rwklx,
  deny @{PROC}/mem rwklx,
  deny @{PROC}/kmem rwklx,
  deny @{PROC}/kcore rwklx,
  
  deny mount,
  
  deny /sys/[^f]*/** wklx,
  deny /sys/f[^s]*/** wklx,
  deny /sys/fs/[^c]*/** wklx,
  deny /sys/fs/c[^g]*/** wklx,
  deny /sys/fs/cg[^r]*/** wklx,
  deny /sys/firmware/efi/efivars/** rwklx,
  deny /sys/kernel/security/** rwklx,

  ## == POST END == ##

}
`

	var profile = Profile{
		Name: "test",
		ProfileHeader: ProfileHeader{
			File:         true,
			Network:      false,
			Capabilities: true,
		},
		Rules: Rules{
			FilePaths: []RuleConfig{
				{
					Value: "/etc/",
					Dir:   true,
					Deny:  true,
				},
				{
					Value:     "/var/",
					Dir:       true,
					Recursive: true,
					OwnerOnly: true,
				},
				{
					Value: "/secret.txt",
					Deny:  true,
				},
				{
					Value:    "/plain.txt",
					Deny:     true,
					ReadOnly: true,
				},
				{
					Value:     "/config.txt",
					Deny:      true,
					OwnerOnly: true,
					ReadOnly:  true,
				},
			},
			ProcessPaths: []RuleConfig{
				{
					Value:     "/bin/sleep",
					Deny:      true,
					OwnerOnly: true,
				},
				{
					Value: "/bin/ls",
					Deny:  true,
				},
				{
					Value: "/bin/cat",
				},
			},
			NetworkRules: []RuleConfig{
				{
					Value: "tcp",
				},
			},
			CapabilitiesRules: []RuleConfig{
				{
					Value: "chown",
					Deny:  true,
				},
			},
		},
		FromSource: map[string]FromSourceConfig{
			"/bin/cat": {
				Fusion: true,
				ProfileHeader: ProfileHeader{
					File:         true,
					Network:      false,
					Capabilities: true,
				},
				Rules: Rules{
					FilePaths: []RuleConfig{
						{
							Value: "/etc/",
							Dir:   true,
							Deny:  true,
						},
						{
							Value: "/secret.txt",
							Deny:  true,
						},
						{
							Value:    "/plain.txt",
							Deny:     true,
							ReadOnly: true,
						},
						{
							Value:     "/config.txt",
							Deny:      true,
							OwnerOnly: true,
							ReadOnly:  true,
						},
					},
				},
			},
		},
	}

	// Create a new template and parse the letter into it.
	t := template.Must(template.New("apparmor").Parse(profiletmpl))

	// Execute the template for each recipient.
	err := t.Execute(os.Stdout, profile)
	if err != nil {
		log.Println("executing template:", err)
	}
}
