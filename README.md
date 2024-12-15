# vladinject - dll injector written in rust
supports injection to both native x64 and wow64 processes<br>
gui written using egui

![Inject Running](images/running.png)
![Inject New](images/new.png)<br>

Running injection is done via CreateRemoteThread<br>
New process injection is done via APC queue
