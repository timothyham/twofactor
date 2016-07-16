twofactor
========

This is a command line version of the Google Authenticator App.
It will read the secrets file at $HOME/.twofactor and print out the codes and time to expire

The secrets file is in following format:

    Label1:SECRET_KEY
    Label2:ANOTHER_SECRET_KEY
