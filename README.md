# awsdns - DNS naming for your EC2 instances

`awsdns` is a DNS server that lets you discover EC2 instances by a name you assign them (via tags).

Possible uses:

* **Configuring dependencies by name**: For example, your application might need a mail server, a file sever, and a database server. You can give those servers meaningful names like `mailserver.awsdns.` instead of hard-coding IPs in your config files.
* **Adapting to infrastructure changes**: On ephemeral machines, IP address change all the time. Usign a DNS name lets all machines that depend on it discover the new one, without reconfiguring anything. This helps you when you start/stop machines, replace them with different instance types or for auto-scaling groups.
* **Load balancing**: If several instances have the same name, `awsdns` will resolve their names randomly, spreading the worload evenly between them.

How does it work?

* Add a tag called `awsdns` to the EC2 instances you want to give a name. The value of this tag will become the DNS name of the instance.
* Run `awsdns` as a local DNS server and configure it as your DNS server.
* Look up any EC2 instance by using the name you assigned.

## Running `awsdns`

Make sure your EC2 instances have a tag that you can use to refer to them (for example, you can use the tag `awsdns`), set a value like `mailserver`. This instance will get a name like `mailserver.awsdns.`.

`awsdns` accepts the following configuration parameters:

* `--bind=ipaddress:port`: binding address and port. Sets both TCP and UDP. By default, `127.0.0.1:53`. Please note that you will need to be root to be able to access port 53.
* `--ttl=seconds`: time that the results will remain in cache, in seconds. This value is used for the TTL in the answers, so clients can cache them, and also internally for caching the responses given by AWS. By default, `30`.
* `--tag=tagname`: tag name in EC2 that contains the DNS name. By default, `awsdns`.
* `--alternateDNS=dns-server:port`: DNS server to resolve names not in the `awsdns.` domain. By default, `169.254.169.253:53`, which is an AWS server available to EC2 instances.
* `--verbose`: Chattier version with some debugging information

Once you have `awsdns` running, you may want to edit your `/etc/resolv.conf` file to point to it.

### AWS Region

Region is taken from, in this order:

* `AWS_REGION` environment variable
* `~/.aws/config` file, if no environment variable is configured
* Region where the instance is running, if you're running in EC2 and no environment variable nor config file is configured

You can configure the region in the `~/.aws/config` file, like this:

```
[default]
region = us-east-1
```

Region can also be configured with the `AWS_REGION` environment variable. For example `AWS_REGION=us-east-1`.

### AWS Credentials

Credentials are taken from, in this order:

* `AWS_PROFILE` environment variable
* `~/.aws/credentials` file, if no environment variable is configured
* IAM profile associated to the instance, if you're running in EC2, if you're running in EC2 and no environment variable nor credentials file is configured

You will need AWS credentials to describe instances. Credentials can be supplied in an 
`~/.aws/credentials` file, which might look like:

```
[default]
aws_access_key_id = AKID1234567890
aws_secret_access_key = MY-SECRET-KEY
```

If you have several profiles, you can select the profile using the `AWS_PROFILE` environment variable.

You can learn more about the credentials file from this
[blog post](http://blogs.aws.amazon.com/security/post/Tx3D6U6WSFGOK2H/A-New-and-Standardized-Way-to-Manage-Credentials-in-the-AWS-SDKs).

Alternatively, you can set the following environment variables:

```
AWS_ACCESS_KEY_ID=AKID1234567890
AWS_SECRET_ACCESS_KEY=MY-SECRET-KEY
```

#### AWS Policy

The credentials you provide need to have access to the describe-instances EC2 API. You will need a policy similar (or identical) to this one:

```
{
    "Statement": [
        {
            "Action": [
                "ec2:DescribeInstances"
            ],
            "Effect": "Allow",
            "Resource": [
                "*"
            ]
        }
    ],
    "Version": "2012-10-17"
}
```