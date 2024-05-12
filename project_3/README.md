<h1 align='center'> Project III </h1>
<h2 align='center'> Ransomware Propagation and Payload </h2>

#### Tasks

- [x] Task I   - Crack SSH password
    - [x] use itertools to generate combinations
    - [x] use paramiko to connect to the victim
- [x] Task II  - Create a compression virus with the propagation of the ransomware worm
    - [x] fetch worm from the attacker server
    - [x] execute which to find the path of `ls`
    - [x] compress the virus
    - [x] pad the virus's size to make it as large as `ls`
    - [x] modify the last few bytes of the virus
- [ ] Task III - Prepare the ransomware payload
    - [ ] execute `ls` and pass all the arguments
