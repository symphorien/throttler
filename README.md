# throttler
```throttler``` slows processes down when temperature rises. 

The principle is inspired of ```cpulimit``` : cycles of ```SIGSTOP``` and ```SIGCONT``` to slow down the execution of greedy processes.

When starting throttler, you should specify a *min_temp* (with ```-t```) and a *max_temp* (with ```-T```). 
Below min_temp, no throttling at all is done. 
Above, the maximal cpu usage for any process decreases linearly from 1 (100%) at *min_temp* to *min_cpu* (customisable with ```-m```) at *max_temp* and above.

Some processes can't/shouldn't be suspended :
* ```init```
* ```throttler``` itself
* processes of other users (```throttler``` doesn't even try to kill them, capabilities won't do the trick)
* processes with nice < 0
* processes owning a tty (notably children of a shell with job control activated) : use ```-x```

```throttler``` doesn't take into account the number of cores of your system. 
With ```-m 0.01```, a targeted process may use as much as ```n %``` of CPU where ```n``` is the number of cores.

###Building

Use ```cargo```.
