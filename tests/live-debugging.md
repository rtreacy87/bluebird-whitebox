# Live-Debugging Java Applications

## Introduction

Since we have the`JAR`file, we can use[Visual Studio Code](https://code.visualstudio.com/)or[Eclipse IDE](https://www.eclipse.org/)to remotely debug the application and see how our input is handled in real-time.

## Remote Debugging with Visual Studio Code

The first thing that we want to do, is install the[Extension Pack for Java](https://marketplace.visualstudio.com/items?itemName=vscjava.vscode-java-pack)for`VSCode`.

Once that's been installed, we're going to decompile`BlueBird`(if you haven't already) using`Fernflower`. As a reminder, this is what the commands look like:

```
icantthinkofaname23@htb[/htb]`$mkdirsrc$java -jar fernflower.jar BlueBird-0.0.1-SNAPSHOT.jar src$cdsrc$jar -xf BlueBird-0.0.1-SNAPSHOT.jar`
```

At this point, we can launch`VSCode`and open the folder`src/BOOT-INF/classes`. We should have all the source files open, but a lot of lines will be underlined in red due to unresolved imports. We can fix this by navigating to`Java Projects > Referenced Libraries`on the lefthand sidebar, clicking the`+`icon and selecting all the`JAR`files from the decompiled`src/BOOT-INF/lib`folder. After this is done, the errors should disappear.

![File explorer in Visual Studio Code showing a list of JAR files in the "lib" directory. Java project structure on the left with classes and referenced libraries.](https://academy.hackthebox.com/storage/modules/188/debugging/9.png)

Now, we want to hit`[CTRL]+[SHIFT]+[D]`to bring up the debug pane, and`create a launch.json file`with the following contents:

Code:json```
`{"version":"0.2.0","configurations":[{"type":"java","name":"Remote Debugging","request":"attach","hostName":"127.0.0.1","port":8000}]}`
```

Once all of this prepared, we will connect to the VM using SSH while forwarding port`8000`.

```
icantthinkofaname23@htb[/htb]`$ssh-L8000:127.0.0.1:8000 student@x.x.x.x`
```

Then, we can run the command below to launch`BlueBird`in remote debugging mode.

```
`student@bb01:~$java -Xdebug -Xrunjdwp:transport=dt_socket,address=8000,server=y,suspend=y -jar /opt/bluebird/BlueBird-0.0.1-SNAPSHOT.jarListening for transport dt_socket at address: 8000`
```

Finally, we can go back to`VSCode`and hit`[F5]`to start debugging. You can set a breakpoint by left-clicking to the left of a line number like this:

![Visual Studio Code showing IndexController.java with a breakpoint set at line 37. The code includes methods for handling requests and user authentication. Project structure visible on the left.](https://academy.hackthebox.com/storage/modules/188/debugging/10.png)

When lines with breakpoints are hit, execution will pause so that you can inspect variable values and control the program's flow by stepping through the lines of code.

![Visual Studio Code in debug mode showing IndexController.java. Variables panel displays local variables. Code includes SQL query and user authentication logic. Breakpoint at line 37, current line highlighted.](https://academy.hackthebox.com/storage/modules/188/debugging/11.png)

## Remote Debugging with Eclipse

Perhaps you're a fan of`Eclipse`. That's alright, the process is quite similar in this case. Go ahead and create a`new Java Project`with the following settings:

![New Java Project setup window. Project name: BlueBird. Default location selected. JRE: JavaSE-17. Project layout: separate folders for sources and class files. Options for working sets and module creation. Back, Next, Cancel, and Finish buttons.](https://academy.hackthebox.com/storage/modules/188/debugging/1.png)

We are going to import the "source" of`BlueBird`into the`Eclipse`project, so if you haven't already, decompile`BlueBird-0.0.1-SNAPSHOT.jar`using`Fernflower`as described in the`Decompiling Java Archives`section. Once that's ready, go ahead and copy the contents of the decompiled`classes/`folder into the`src/`folder for the`Eclipse`project we just made.

```
icantthinkofaname23@htb[/htb]`$cp-r src/BOOT-INF/classes/* ~/eclipse-workspace/BlueBird/src`
```

If you did that correctly, right-clicking in the`Package Explorer`and hitting`Refresh`should result in all the packages showing up (with red errors).

![Eclipse IDE showing the Package Explorer with the BlueBird project. Includes JRE System Library [JavaSE-17], source folders for bluebird, controller, model, security, templates, static, and application properties.](https://academy.hackthebox.com/storage/modules/188/debugging/2.png)

The reason the packages have errors is due to missing imports. To resolve this issue, we will import all the dependencies from the decompiled JAR. Go to`File > Properties > Java Build Path > Libraries > Modulepath > Add External JARs`and add all the JAR files from`lib/`(created by`Fernflower`when decompiling). Click`Apply and Close`once imported.

![Eclipse IDE Java Build Path settings for BlueBird project. Libraries tab selected, showing Modulepath with JRE System Library [JavaSE-17]. Options to add JARs, external JARs, variables, libraries, and class folders. Apply and Close buttons.](https://academy.hackthebox.com/storage/modules/188/debugging/3.png)

If you did this step correctly, there should be no more red error signs or underlines on import statements as show in the screenshot below.

![Eclipse IDE showing BlueBirdApplication.java. The code imports org.springframework.boot.SpringApplication and defines the main class with a SpringApplication.run method. Project structure visible on the left.](https://academy.hackthebox.com/storage/modules/188/debugging/4.png)

At this point we can open up a terminal and run the following command to start the JAR file in`remote debugging`mode.

```
icantthinkofaname23@htb[/htb]`$java -Xdebug -Xrunjdwp:transport=dt_socket,address=8000,server=y,suspend=y -jar BlueBird-0.0.1-SNAPSHOT.jarPicked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
Listening for transport dt_socket at address: 8000`
```

To attach to this, we need to head back to`Eclipse`, go to`Run > Debug Configurations`and create a new`Remote Java Application`with the following settings (should be default):

![Debug Configurations window for a Remote Java Application. Project: BlueBird. Connection type: Standard (Socket Attach). Host: localhost, Port: 8000. Options to allow termination of remote VM. Revert, Apply, Close, and Debug buttons.](https://academy.hackthebox.com/storage/modules/188/debugging/5.png)

Click`Apply`and then`Debug`. If you look at the console, you should see the Spring startup log messages.

![Terminal output showing Spring Boot application startup. Command to run BlueBird-0.0.1-SNAPSHOT.jar with debug options. Listening on port 8000. Logs indicate application start, repository configuration, and Tomcat server initialization on port 8080.](https://academy.hackthebox.com/storage/modules/188/debugging/8.png)

Inside`Eclipse`click`Window > Perspective > Open Perspective > Debug`to show the debugging windows. At this point we can place breakpoints in the project and live-debug`BlueBird`. To to so, right-click on the line number and select`Toggle Breakpoint`. When this line will be reached, the application will freeze and we can step through execution line by line to see what happens exactly. You can see the values of variables as they change in the`Variables`window (just make sure the`Debug Perspective`is open).

![IDE showing AuthController.java with a method for password reset. Includes SQL query to select users by email, validation, and error handling. Variables panel displays current values, including the SQL query.](https://academy.hackthebox.com/storage/modules/188/debugging/6.png)

## Conclusion

`Live debugging`can be a very powerful technique, but it will not always work 100% correctly since we are working with`decompiled`source code and not with the actual source code. In the end, everybody has their own preferred workstyles, so the best thing is to just try it out and see for yourself.
