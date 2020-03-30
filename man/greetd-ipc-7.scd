greetd-ipc(7)

# NAME

greetd-ipc - IPC protocol for greetd

# DESCRIPTION

This details the interprocess communication (IPC) protocol for *greetd*(1).
This IPC protocol can be used to create and manage sessions under greetd.

The IPC protocol uses a UNIX socket as a method of communication. The path
to the socket is stored in the environment variable _GREETD_SOCK_.

# MESSAGE AND REPLY FORMAT

The format for messages and replies is:
```
<payload-length> <payload>
```
Where
```
<payload-length> is a 32-bit integer in native byte order
<payload> is a UTF-8-encoded JSON string.
```

For example, sending the "create_session" command would look like the
following hexdump:
```
00000000  2c 00 00 00 7b 22 74 79  70 65 22 3a 20 22 63 72  |,...{"type": "cr|
00000010  65 61 74 65 5f 73 65 73  73 69 6f 6e 22 2c 20 22  |eate_session", "|
00000020  75 73 65 72 6e 61 6d 65  22 3a 20 22 6d 65 22 7d  |username": "me"}|
```

# MESSAGES

## Requests

[[ *MESSAGE TYPE*
:[ *FIELDS*
:< *PURPOSE*
|  create_session
:  username (string)
:  Creates a session and initiates a login attempted for the given user. The session is ready to be started if a success is returned.
|  post_auth_message_response
:  response (string, optional)
:  Answers an authentication message. If the message was informative (info, error), then a response does not need to be set in this message. The session is ready to be started if a success is returned.
|  start_session
:  cmd (array of strings)
:  Requests for the session to be started using the provided command line. The session will start after the greeter process terminates.
|  cancel_session
: 
:  Cancels the session that is currently under configuration.

## Responses
[[ *MESSAGE TYPE*
:[ *FIELDS*
:< *PURPOSE*
|[ success
: 
:  Indicates that the request succeeded.
|  error
:  error_type (enum as string), description (string)
:  Indicates that the request failed.
|  auth_message
:  auth_message_type (enum as string), auth_message (string)
:  Indicates that an authentication message needs to be answered to continue through the authentication flow. There are no limits on the number and type of messages that may be required for authentication to succeed, and a greeter should not make any assumptions about the messages. Must be answered with either post_auth_message_response or cancel_session.

## Authentication message type enums

[[ *AUTH MESSAGE TYPE*
:[ *PURPOSE*
|  visible
:  Indicates that input from the user should be visible when they answer this question.
|  secret
:  Indicates that input from the user should be considered secret when they answer this question.
|  info
:  Indicates that this message is informative, not a question.
|  error
:  Indicates that this message is an error, not a question.

## Error enums

[[ *ERROR TYPE*
:[ *PURPOSE*
|  auth_error
:  Indicates that authentication failed. This is not a fatal error, and is likely caused by incorrect credentials. Handle as appropriate.
|  error
:  A general error. See the error description for more information.

# AUTHORS

Maintained by Kenny Levinsen <contact@kl.wtf>. For more information about
greetd development, see https://git.sr.ht/~kennylevinsen/greetd.

# SEE ALSO
*greetd*(1)