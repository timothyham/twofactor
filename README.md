twofactor
========

This is a command line version of the Google Authenticator App.
It will read the secrets file at $HOME/.twofactor and print out the codes and time to expire

The secrets file is in following format:

    Label1:SECRET_KEY
    Label2:ANOTHER_SECRET_KEY

Run `go install` to build and install.

Clock skew: If your clock is off, it may not generate the correct codes. Use 
`twofactor 2+` to generate codes one minute in the future (the clock is slow), or 
`twofactor 2-` to generate codes one minute in the past (the clock is fast).
