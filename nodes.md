## Big Ideas:
- data is protected by something someone knows, something they have, or something they are
- passwords are the most common way (something they know)
- people are trying to always get other people's passwords
- if they are easy to guess, then they are vulnerable
- if they are stored in an insecure store, or a single point of access store
  (like a database)), they are vulnerable
- password hashing is the answer ... store the hash, not the password.
- we are using bcryptjs to generate hashes (the javascript module for the bcrypt
  algorithm)
- in a login attempt, a username and password are supplied. The username is used to find the user and their password in the database
- a password guess supplied in a login attempt is used to generate a hash, which is compared to the stored hash for the real password
- knowing the stored hash doesn't help - if you supply the hash, it's as good as the wrong password.
- rainbow tables are hackers' answer - use a lot of computing power to generate hash's for every possible password
 if they can get access to a data store that contains a list of hashes, they compare the hashes to the hashes in their table, and then they know what password was used to generate that hash.
- if they can get access to a data store that contains a list of hashes, they compare the hashes to the hashes in their table, and then they know what password was used to generate that hash.
- IFF they know what method was used to generate the hashes when they generated the table.
- the list of "every possible password" is governed by 2 things: 1) the list of characters used, and 2) the possible lengths of passwords
- users can put their passwords in a set that is so large that it is unlikely that anyone has tried to generate a hash for it
- methods like bcrypt add another safeguard: use an algorithm for generating hash's that is very complex and time consuming (i.e. "costly"), so that every generation takes a long time
- rainbow tables then have to contain an incredibly large data set that takes an incredibly long time to generate
- keeping authentication status or state on the server requires something called a "session" (it can be called other things, but is often called a session)
- sessions have a limited lifetime
- when a user successfully passes an authentication challenge, a session is established, and a token is given to the app
- the app can use the token in place of making the user authenticate again
- the token has a limited lifetime
- when server-side sessions are used to validate tokens, the token is passed back and forth in a cookie (for HTTP applications)
