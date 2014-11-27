# TCP Relay #

A simple TCP relay based on [libev](http://software.schmorp.de/pkg/libev.html)

## Build ##

```bash
# install libev first
cd tcprelay
make
```

## Usage ##

```bash
usage: tcprelay local_host local_port remote_host remote_port

Examples:
tcprelay 127.0.0.1 5353 8.8.8.8 53
```

## License ##

Copyright (C) 2014, Xiaoxiao <i@xiaoxiao.im>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.
