# Virtual Machine 0

### Information
* Category: RE
* Point:
* Level: Medium

### Description
Can you crack this black box? We grabbed this design doc from enemy servers: Download. We know that the rotation of the red axle is input and the rotation of the blue axle is output. 

### Hint
Rotating the axle that number of times is obviously not feasible. Can you model the mathematical relationship between red and blue?

### Solution
#### What we got ?
- The problem gives us a `.dae` file, so I try to open it with https://3dviewer.net/, hidden all the box's part we will have 2 axles.

    ![3D](https://github.com/UITxWoodyNguyen/CTF/blob/main/Reverse%20Engineering/Medium/Virtual%20Machine%200/vm1.png?raw=true)

#### How to get the flag ?
- Base on the hints, we need to find the mathematical relationship between 2 axles. Moreover, after trying count the number of spikes in 2 axles, the red has 40 and the grey has only 8. Divide 2 numbers of spikes (`40 / 8 = 5`), we can easily get the math relationship:
    ```python
    output = input * 5
    ```
- Try using python to get the output and decode it with Cyberchef to get flag:
    
    ![py](https://github.com/UITxWoodyNguyen/CTF/blob/main/Reverse%20Engineering/Medium/Virtual%20Machine%200/vm2.png?raw=true)

    ![Flag](https://github.com/UITxWoodyNguyen/CTF/blob/main/Reverse%20Engineering/Medium/Virtual%20Machine%200/vm3.png?raw=true)
