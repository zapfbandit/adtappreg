# power-automate-play

## Features to implement

[ ] install setup.exes
[ ] install scripts
[ ] come up with a solution of app > 4GB
[ ] store actual install files rather than intune files
[ ] use blob storage
[ ] required assignments
[ ] other assignment targets (e.g. specific users, specific machines)
[ ] improve script robustness

## How to add application

* Create a new folder (in apps/<app name no spaces>/<app version - a.b.c.d format where a.. are numbers>)
* Add info.yml to that folder (template found in scripts/info.template.yml)
* Fill out as much of that file as you can
* Upload install file to blob storage
  * run 
    * scripts\azcopy.exe login
    * scripts\azcopy.exe sync <local path to folder that contains all setup files> "https://<storage account>.blob.core.windows.net/<container name>/<app name no spaces>/<app version>/remote_files"
  * make sure to update the remoteFilesPaths in info.yml
* Make branch/commit?!?
* Upload app