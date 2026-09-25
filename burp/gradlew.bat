@rem Gradle start-up script for Windows. Standard wrapper launcher.
@if "%DEBUG%"=="" @echo off
set DIRNAME=%~dp0
set WRAPPER_JAR=%DIRNAME%gradle\wrapper\gradle-wrapper.jar
if not exist "%WRAPPER_JAR%" (
  echo gradle-wrapper.jar is missing. Generate it once with a system Gradle:
  echo     gradle wrapper --gradle-version 8.7
  exit /b 1
)
if defined JAVA_HOME (set JAVACMD=%JAVA_HOME%\bin\java.exe) else (set JAVACMD=java)
"%JAVACMD%" -classpath "%WRAPPER_JAR%" org.gradle.wrapper.GradleWrapperMain %*
