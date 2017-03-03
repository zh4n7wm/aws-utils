## aws ec2工具集

只在Python3上测试过。

### 配置aws credentials

请参考：[aws credentials](https://boto3.readthedocs.io/en/latest/guide/configuration.html)

### 为aws ec2主机生成 ssh/assh 配置文件

`gene_ec2_ssh_config.py` 会获取`aws ec2`主机列表，并生成`assh config` 或 `ssh config`，方便`ssh`登陆主机。

#### 命令

参考帮助：

	$ python gene_ec2_ssh_config.py --help
	Usage: gene_ec2_ssh_config.py [OPTIONS]
	
	Options:
	--kind TEXT      Generate assh config or ssh config. Default value: assh
	--profile TEXT   aws profile name. Default value: default
	--region TEXT    aws region name. Default value: us-east-1
	--username TEXT  ec2 instance login username. Default value: centos
	--port INTEGER   ec2 instance sshd listening port. Default value: 22
	--states TEXT    ec2 instance run state list. Default value: ['running']
	--output TEXT    display result to stdout, or write to output file.  Default value: stdout
	--help           Show this message and exit.


生成 assh config:
	
	$ python gene_ec2_ssh_config --kind assh --profile prod --username ec2-user --port 2222
	$ python gene_ec2_ssh_config --kind assh --profile prod --username ec2-user --port 2222 --output /tmp/assh_prod.yml

生成 ssh config:
	
	$ python gene_ec2_config --kind ssh --profile prod --username ec2-user --port 2222
	$ python gene_ec2_config --kind ssh --profile prod --username ec2-user --port 2222 --output /tmp/ssh_prod

## 参考

- [assh](https://github.com/moul/advanced-ssh-config)
- [aws credentials](https://boto3.readthedocs.io/en/latest/guide/configuration.html)
