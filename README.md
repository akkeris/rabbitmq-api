# RabbitMQ Broker for Akkeris

Create virtural hosts and users in a RabbitMQ Cluster.

## Run Time Environment

* CLUSTERS: Comma seperated list of rabbitmq clusters. Ex: sandbox,live
* LIVE_RABBIT_AMQP: hostname to access queues in cluster 'live'. See below
* LIVE_RABBIT_URL: hostname to access management api in cluster 'live'.
* RABBITMQ_ADMIN_USERNAME: the admin username on the rabbitmq clusters
* RABBITMQ_ADMIN_PASSWORD: the admin password on the rabbitmq cluseters
* ENCRYPT_KEY: key used to set passwords in DB (24 characters)
* DATABASE_URL: broker db
* PORT: Port to access this api.  Default is 3000 (See [Go Martini](https://github.com/go-martini/martini))

### For each cluster

* [CLUSTER_NAME]_RABBIT_URL - Api hostname (can be same as queue hostname)
    * Ex: LIVE_RABBIT_URL=rabbitmq-prod.example.com
    * Ex: SANDBOX_RABBIT_URL=rabbitmq-sandbox-api.example.io
* [CLUSTER_NAME]_RABBIT_AMQP - Queues hostname
    * Ex: LIVE_RABBIT_AMQP=rabbitmq-prod.example.com
    * Ex: SANDBOX_RABBIT_AMQP=rabbitmq-sandbox.example.io

## API

### Get list of plans

Get a list of plans that can be used.  The plans correlate to the cluster
names, so each cluster needs to be configured as a plan.  
The defaults are sandbox and live.

**URL** : `/v1/rabbitmq/plans`

**Method** : `GET`

#### Success Response

**Code** : `200 OK`

**Content**


```json
{
    "live":"Prod and real use. Bigger cluster.  Not purged",
    "sandbox":"Dev and Testing and QA and Load testing.  May be purged regularly"
}

```

## Create instance

Create a virtual host and user in the cluster from the plan.

**URL** : `/v1/rabbitmq/instance`

**Method** : `POST`

**Data** All fields required

```json
{
  "plan": "live",
  "billingcode":"MyTeam"
}
```

### Success Response

**Condition** Virtual host and user created and added to database.

**Code** : `201 CREATED`

**Content** 

```json
{
  "RABBITMQ_URL":"amqp://username:password@rabbitmq-sandbox.example.io:5672/username"
}
```

### Error Response >>>**TODO**<<<

**Condition** : Invalid plan or plan missing

**Code** : `400 Bad Request`

**Returned Response** : None

## Get queue connection url for virtual host

**URL** : `/v1/rabbitmq/url/:vhost`

**Method** : `GET`

### Success Response

**Condition** : Virtual host found

**Content** :

```json
{
  "RABBITMQ_URL":"amqp://username:password@rabbitmq-sandbox.example.io:5672/vhost"
}
```

### Error Response

**Condition** : Virtual host not found

**Code** : `404 Not Found`

## Delete user and vhost

**URL** : `/v1/rabbitmq/instance/:vhost`

**URL Parameters** : `username=[string]`

**Method** : `DELETE`

### Success response

**Condition** : Virtual host and user deleted from database and rabbitmq cluster.

**Code** : `200 OK`

**Content** : None

### Error response >>>**TODO**<<<

**Condition** : Virtual host not found in DB

**Code** : `404 Not Found`

**Content** : None

## Add tag to user in database

**URL** : `/v1/tag`

**Method** : `POST`

**Data** : 
* resource: virtual host name
* name: tag name
* value: tag value

```json
{
  "resource":"VHOST",
  "name":"owner",
  "value":"Captain Janeway"
}
```
	
### Success response

**Condition** : Tag was added to virtual host in database

**Code** : `201 Created`

**Content** :

```json
{
  "response":"tag added"
}
```

### Error response >>>**TODO**<<<

**Condition** : Vhost no in database

**Code** : `404 Not found`

# TODO

* Document structures and functions
* Add error handling
