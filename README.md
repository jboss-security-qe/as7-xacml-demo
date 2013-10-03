# AS7/EAP6 XACML demo application

Sample web application with XACML authorization for JBoss AS7 (and EAP 6)

## Requirements

You'll need Java 6 and also some other tools to run this demo.

### AS7 or EAP6
We suggest usage **EAP 6.1.0.Beta** from [JBoss AS download page](http://www.jboss.org/jbossas/downloads)

If you like to try the demo with AS 7.1.1.Final, then you have to fix file `Picketbox` module file
`[inst]/modules/org/picketbox/main/module.xml`. Add `org.jboss.security.xacml` module dependency there 
(cf. [fix in repo](https://github.com/wildfly/wildfly/commit/5cab9a8220b9bc9f1181038d4ad7b5032c32b4fe))

Run standalone server:

	$ export JBOSS_HOME=/path/to/jboss-installation
	$ cd $JBOSS_HOME/bin
	$ ./standalone.sh

Configure **xacml-demo security domain** using CLI:

	$ ./jboss-cli.sh -c

and run commands:

	/subsystem=security/security-domain=xacml-demo:add(cache-type=default)
	/subsystem=security/security-domain=xacml-demo/authentication=classic:add(login-modules=[{"code"=>"UsersRoles", "flag"=>"required"}]) {allow-resource-service-restart=true}
	/subsystem=security/security-domain=xacml-demo/authorization=classic:add(policy-modules=[{"code"=>"org.jboss.test.xacml.CustomXACMLAuthorizationModule", "flag"=>"required"}]) {allow-resource-service-restart=true}

### Git and Maven 

You should have [git](http://git-scm.com/) installed

	$ git clone git@github.com:jboss-security-qe/as7-xacml-demo.git

or you can download [current sources as a zip file](https://github.com/jboss-security-qe/as7-xacml-demo/archive/master.zip)

You need also a [Maven](http://maven.apache.org/) installed

	$ cd as7-xacml-demo
	$ mvn clean package
	$ cp target/as7-xacml-demo.war "$JBOSS_HOME/standalone/deployments/"

## Test the demo

Go to [http://localhost:8080/as7-xacml-demo/](http://localhost:8080/as7-xacml-demo/) and try to login using credentials:
 * *admin/admin* - you will get access to an index page
 * *user/user* - you will be logged in, but access will be denied (HTTP status 403 returned)

## License

* [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
