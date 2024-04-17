# ConTacGen-Plugin 2.0
ConTacGen is a contextual cyber-attack data generator for Weka.

## Installation

### Windows

1. **Install [Weka](https://waikato.github.io/weka-wiki/downloading_weka/)**

2. **Install [Docker Desktop for Windows](https://docs.docker.com/desktop/install/windows-install/)**, then **open it** and:
   - Go to **`Settings`** : 
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

3. **Install [JDK for Windows](https://www.oracle.com/java/technologies/downloads/#jdk22-windows)**

4. **Install [Apache Ant](https://ant.apache.org/manual/install.html)**

5. **Go to** [Usage](#usage) section to use the plugin

### Linux

1. **Install [Weka](https://waikato.github.io/weka-wiki/downloading_weka/)**

2. **Install JDK:**
   ```
     sudo apt install default-jdk
   ```

3. **Install Ant:**
   ```
   sudo apt install ant
   ```

4. **Install Docker:**
   - [Docker for Ubuntu](https://docs.docker.com/engine/install/ubuntu/)
   - [Post-installation steps for Linux](https://docs.docker.com/engine/install/linux-postinstall/)

5. Go to [Usage](#usage) section to use the plugin

## Compatibility

ConTacGen 2.0 has been tested and is compatible with the following software versions:
- **Operating Systems**:
  - Ubuntu 18.04, 20.04, 22.04
  - Windows 10, Windows 11
  - Kali Linux 2022.4 
  - Linux Mint 21.3
- **Weka**: Version 3.9.6 and above
- **JDK**: Version 11 and above
- **Docker Desktop**: Version 4.29.0 and above for Windows
- **Apache Ant**: Version 1.10.2 and above

Please ensure that your system meets these requirements to avoid any issues during installation and operation of the plugin.

## Usage
**Build the plugin**
 
In a terminal/command prompt at the root of the ContacGen directory, execute :
```
ant make_package -Dpackage=ConTacGen
```
Plugin will be located inside `/ContacGen/dist/ContacGen.zip`

**Install Plugin in Weka:**

   - Start Weka, go to `Tools` > `Package Manager`, select `Unofficial`, then `file/url` and choose `ConTacGen.zip`. Finally, click on `install` and restart Weka.

On the Weka main page, select `Workbench`, then `Generate`. Choose to select `ConTacGen` under the classification directory, then click `Generate` to start the data generator.
> **The first use will take more time**, depending on your internet connection as you need to pull the docker image (only for the first use)

![image](https://github.com/HyperLan-git/ConTackGen-Plugin/assets/60754866/0872381e-9ca9-4ccd-839f-06ae546c2bde)
> Select "Edit..." to view data details.

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
- Youness Rekik (youness.rekik@epita.fr)

Supervised by **Nidà MEDDOURI** (nida.meddouri@epita.fr)
