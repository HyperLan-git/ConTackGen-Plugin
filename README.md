# ConTackGen-Plugin
ConTackGen is a contextual cyber-attack data generator for Weka.

## Installation


### Windows

1. **Install [Weka](https://waikato.github.io/weka-wiki/downloading_weka/)**

2. **Install and configure Docker Desktop (do not forget to install WSL as well):**
   - [Docker Desktop for Windows](https://docs.docker.com/desktop/install/windows-install/)
   - **Go to 'Settings':** 
   - *General* -> Enable ``Expose daemon on tcp://localhost:2375 without TLS``
   - *Docker Engine:* -> Replace the existing JSON configuration with:
     ```json
     {
       "builder": {
         "gc": {
           "defaultKeepStorage": "20GB",
           "enabled": true
         }
       },
       "experimental": false,
       "hosts": [
         "tcp://0.0.0.0:2375"
       ]
     }
     ```
    Apply and Restart

4. **Install JDK for Windows:**
   - [JDK for Windows](https://www.oracle.com/java/technologies/downloads/#jdk22-windows)


5. **Install Ant:**
   - [Download Apache Ant](https://ant.apache.org/manual/install.html)


### Linux

1. **Install [Weka](https://waikato.github.io/weka-wiki/downloading_weka/)**

2. **Install JDK:**
   - Execute: `sudo apt install default-jdk`

3. **Install Ant:**
   - Execute: `sudo apt-get install ant`

4. **Install Docker:**
   - [Docker for Ubuntu](https://docs.docker.com/engine/install/ubuntu/)
   - [Post-installation steps for Linux](https://docs.docker.com/engine/install/linux-postinstall/)


## Usage
**Build the Plugin:**
   - In Command Prompt/Terminal, execute: `ant make_package -Dpackage=ConTackGen`

**Install Plugin in Weka:**
   - Start Weka, go to `Tools` > `Package Manager`, select `Unofficial`, then `file/url` and choose `ConTackGen.zip`. Finally, click on `install` and restart Weka.

On the Weka main page, select `Workbench`, then `Generate`. Choose to select `ConTackGen` under the classification directory, then click `Generate` to start the data generator.

![image](https://github.com/HyperLan-git/ConTackGen-Plugin/assets/60754866/0872381e-9ca9-4ccd-839f-06ae546c2bde)
> Select "edit" to view data details.

## Authors
> Version 1.0:
- Mathieu SALLIOT (mathieu.salliot@epita.fr)
- Pierre BLAIS (pierre.blais@epita.fr)
- Luis RIBEIRO (luis.rebeiro@epita.fr)
- Benjamin ALONZEAU (benjamin.alonzo@epita.fr)

> Version 2.0:
- Aboubekre Sayoud (aboubekre.sayoud@epita.fr)
- Simon Defoort (simon.defoort@epita.fr)
- Natale Mamberti (natale.mamberti@epita.fr)
-  Youness Rekik (youness.rekik@epita.fr)

Supervised by **Nidà MEDDOURI** (nida.meddouri@epita.fr)
