package main

import "github.com/martini-contrib/binding"

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"github.com/bitly/go-simplejson"
	"github.com/go-martini/martini"
	_ "github.com/lib/pq"
	"github.com/martini-contrib/render"
	"github.com/nu7hatch/gouuid"
)

type ClusterInfo struct {
	Url      string
	Username string
	Password string
	Amqp     string
	Cluster  string
}

var clusters []ClusterInfo
var key []byte
var brokerdb string

func main() {
	populateClusterInfo()
	m := martini.Classic()
	m.Use(render.Renderer())
	m.Get("/v1/rabbitmq/plans", plans)
	m.Post("/v1/rabbitmq/instance", binding.Json(provisionspec{}), provision)
	m.Get("/v1/rabbitmq/url/:name", url)
	m.Delete("/v1/rabbitmq/instance/:vhost", Delete)
	m.Post("/v1/tag", binding.Json(tagspec{}), tag)
	m.Run()

}

type provisionspec struct {
	Plan        string `json:"plan"`
	Billingcode string `json:"billingcode"`
}

func store(cluster string, vhost string, username string, password string, billingcode string) {
	uri := brokerdb
	db, err := sql.Open("postgres", uri)
	if err != nil {
		fmt.Println(err)
	}
	var newname string
	err = db.QueryRow("INSERT INTO provision(cluster,vhost,username,password_enc,billingcode) VALUES($1,$2,$3,$4,$5) returning username;", cluster, vhost, username, Encrypt(password), billingcode).Scan(&newname)

	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(newname)
	err = db.Close()
}
func retreive(v string) (c string, vh string, u string, p string, t []tagspec) {
	uri := brokerdb
	db, err := sql.Open("postgres", uri)
	if err != nil {
		fmt.Println(err)
	}
	stmt, err := db.Prepare("select cluster,vhost,username,password_enc,tags from provision where vhost = $1 ")
	if err != nil {
		fmt.Println(err)
	}
	defer stmt.Close()
	rows, err := stmt.Query(v)
	defer rows.Close()
	var cluster string
	var vhost string
	var username string
	var password_enc string
	var tags []byte
	for rows.Next() {
		err := rows.Scan(&cluster, &vhost, &username, &password_enc, &tags)
		if err != nil {
			fmt.Println(err)
			db.Close()
		}
	}
	fmt.Println(cluster)
	fmt.Println(vhost)
	fmt.Println(username)
	fmt.Println(password_enc)
	fmt.Println(Decrypt(password_enc))
	var tagsa []tagspec
	json.Unmarshal(tags, &tagsa)
	for _, element := range tagsa {
		fmt.Println(element.Resource)
		fmt.Println(element.Name)
		fmt.Println(element.Value)
	}
	db.Close()
	return cluster, vhost, username, Decrypt(password_enc), tagsa

}
func Delete(params martini.Params, r render.Render) {
	err := delete(params["vhost"])
	if err != nil {
		r.JSON(500, err)
	}
	r.JSON(200, nil)
}

func delete(vhost string) error {

	cluster, _, _, _, _ := retreive(vhost)

	clusterinfo := clusterInfo(cluster)
	username := clusterinfo.Username
	password := clusterinfo.Password
	auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))

	client := &http.Client{}
	request, _ := http.NewRequest("DELETE", "http://"+clusterinfo.Url+":15672/api/vhosts/"+vhost, nil)
	request.Header.Add("Authorization", "Basic "+auth)
	request.Header.Add("Content-type", "application/json")
	response, _ := client.Do(request)
	defer response.Body.Close()
	_, _ = ioutil.ReadAll(response.Body)

	uri := brokerdb
	db, dberr := sql.Open("postgres", uri)
	if dberr != nil {
		fmt.Println(dberr)
		return dberr
	}

	fmt.Println("# Deleting")
	stmt, err := db.Prepare("delete from provision where vhost=$1")
	if err != nil {
		return err
	}
	res, err := stmt.Exec(vhost)
	if err != nil {
		return err
	}
	affect, err := res.RowsAffected()
	if err != nil {
		return err
	}
	fmt.Println(affect, "rows changed")

	return nil
}

func url(params martini.Params, r render.Render) {
	rcluster, rvhost, rusername, rpassword, _ := retreive(params["name"])
	url := clusterInfo(rcluster).Amqp
	amqp := "amqp://" + rusername + ":" + rpassword + "@" + url + ":5672/" + rvhost
	fmt.Println(amqp)
	r.JSON(200, map[string]string{"RABBITMQ_URL": amqp})
}
func provision(spec provisionspec, err binding.Errors, r render.Render) {
	fmt.Println(spec)
	cluster := spec.Plan
	billingcode := spec.Billingcode

	newusername, newpassword := createuserandpassword()
	create(cluster, newusername, newusername, newpassword)
	fmt.Println(newusername)
	fmt.Println(newpassword)
	store(cluster, newusername, newusername, newpassword, billingcode)
	rcluster, rvhost, rusername, rpassword, _ := retreive(newusername)
	url := clusterInfo(rcluster).Amqp
	amqp := "amqp://" + rusername + ":" + rpassword + "@" + url + ":5672/" + rvhost
	fmt.Println(amqp)
	r.JSON(201, map[string]string{"RABBITMQ_URL": amqp})

}
func createuserandpassword() (ur string, pr string) {

	u, _ := uuid.NewV4()
	newusername := "u" + strings.Split(u.String(), "-")[0]
	p, _ := uuid.NewV4()
	newpassword := "p" + strings.Split(p.String(), "-")[0]
	return newusername, newpassword
}

func create(cluster string, vhost string, newusername string, newpassword string) {

	createvhost(cluster, vhost)
	createUser(cluster, newusername, newpassword)
	grantUser(cluster, newusername, vhost)
	grantAdmin(cluster, vhost)
	createMirrorPolicy(cluster, vhost)
	createTestQueue(cluster, vhost, newusername, newpassword)
}

func clusterInfo(cluster string) ClusterInfo {
	var clusterinfo ClusterInfo
	//clusterinfo.Url = os.Getenv(strings.ToUpper(cluster) + "_RABBIT_URL")
	//clusterinfo.Username = os.Getenv(strings.ToUpper(cluster) + "_RABBIT_USERNAME")
	//clusterinfo.Password = os.Getenv(strings.ToUpper(cluster) + "_RABBIT_PASSWORD")
	//clusterinfo.Amqp = os.Getenv(strings.ToUpper(cluster) + "_RABBIT_AMQP")
	for _, element := range clusters {
		if element.Cluster == cluster {
			clusterinfo = element
		}
	}
	return clusterinfo
}

func grantUser(cluster string, newusername string, vhost string) {

	type Permissions struct {
		Configure string `json:"configure"`
		Write     string `json:"write"`
		Read      string `json:"read"`
	}
	clusterinfo := clusterInfo(cluster)
	var permissions Permissions
	permissions.Configure = ".*"
	permissions.Write = ".*"
	permissions.Read = ".*"

	str, err := json.Marshal(permissions)
	if err != nil {
		fmt.Println("Error preparing request")
	}
	jsonStr := []byte(string(str))
	username := clusterinfo.Username
	password := clusterinfo.Password
	auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))

	client := &http.Client{}
	request, _ := http.NewRequest("PUT", "http://"+clusterinfo.Url+":15672/api/permissions/"+vhost+"/"+newusername, bytes.NewBuffer(jsonStr))
	request.Header.Add("Authorization", "Basic "+auth)
	request.Header.Add("Content-type", "application/json")
	response, _ := client.Do(request)
	defer response.Body.Close()
	_, _ = ioutil.ReadAll(response.Body)

}

func grantAdmin(cluster string, vhost string) {

	type Permissions struct {
		Configure string `json:"configure"`
		Write     string `json:"write"`
		Read      string `json:"read"`
	}
	clusterinfo := clusterInfo(cluster)
	newusername := clusterinfo.Username
	var permissions Permissions
	permissions.Configure = ".*"
	permissions.Write = ".*"
	permissions.Read = ".*"

	str, err := json.Marshal(permissions)
	if err != nil {
		fmt.Println("Error preparing request")
	}
	jsonStr := []byte(string(str))
	username := clusterinfo.Username
	password := clusterinfo.Password
	auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))

	client := &http.Client{}
	request, _ := http.NewRequest("PUT", "http://"+clusterinfo.Url+":15672/api/permissions/"+vhost+"/"+newusername, bytes.NewBuffer(jsonStr))
	request.Header.Add("Authorization", "Basic "+auth)
	request.Header.Add("Content-type", "application/json")
	response, _ := client.Do(request)
	defer response.Body.Close()
	_, _ = ioutil.ReadAll(response.Body)

}

func createUser(cluster string, newusername string, newpassword string) {
	type User struct {
		Password string `json:"password"`
		Tags     string `json:"tags"`
	}
	clusterinfo := clusterInfo(cluster)
	var user User
	user.Password = newpassword
	user.Tags = "management"
	str, err := json.Marshal(user)
	if err != nil {
		fmt.Println("Error preparing request")
	}
	jsonStr := []byte(string(str))
	username := clusterinfo.Username
	password := clusterinfo.Password
	auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))

	client := &http.Client{}
	request, _ := http.NewRequest("PUT", "http://"+clusterinfo.Url+":15672/api/users/"+newusername, bytes.NewBuffer(jsonStr))
	request.Header.Add("Authorization", "Basic "+auth)
	request.Header.Add("Content-type", "application/json")
	response, _ := client.Do(request)
	defer response.Body.Close()
	_, _ = ioutil.ReadAll(response.Body)

}
func createvhost(cluster string, vhost string) {
	clusterinfo := clusterInfo(cluster)
	username := clusterinfo.Username
	password := clusterinfo.Password
	auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))

	client := &http.Client{}
	fmt.Println("http://"+clusterinfo.Url+":15672/api/vhosts/"+vhost)
	request, _ := http.NewRequest("PUT", "http://"+clusterinfo.Url+":15672/api/vhosts/"+vhost, nil)
	request.Header.Add("Authorization", "Basic "+auth)
	request.Header.Add("Content-type", "application/json")
	response, _ := client.Do(request)
	defer response.Body.Close()
	_, _ = ioutil.ReadAll(response.Body)
}

func createMirrorPolicy(cluster string, vhost string) {
	clusterinfo := clusterInfo(cluster)
	username := clusterinfo.Username
	password := clusterinfo.Password
	auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))

	var policyname = "ha-" + vhost
	type PolicyDef struct {
		HAMode     string `json:"ha-mode"`
		HAParams   int    `json:"ha-params"`
		HASyncMode string `json:"ha-sync-mode"`
	}
	type Policy struct {
		Pattern    string    `json:"pattern"`
		Priority   int       `json:"priority"`
		ApplyTo    string    `json:"apply-to"`
		Definition PolicyDef `json:"definition"`
	}

	var policy Policy
	policy.Pattern = ".*"
	policy.Priority = 0
	policy.ApplyTo = "all"
	policy.Definition.HAMode = "exactly"
	policy.Definition.HAParams = 3
	policy.Definition.HASyncMode = "automatic"

	payload, err := json.Marshal(policy)
	if err != nil {
		fmt.Println("Error preparing request")
	}
	jsonStr := (string(payload))
	fmt.Println(jsonStr)

	client := &http.Client{}
	request, _ := http.NewRequest("PUT", "http://"+clusterinfo.Url+":15672/api/policies/"+vhost+"/"+policyname, bytes.NewBuffer(payload))
	request.Header.Add("Authorization", "Basic "+auth)
	request.Header.Add("Content-type", "application/json")
	response, _ := client.Do(request)
	defer response.Body.Close()
	_, _ = ioutil.ReadAll(response.Body)
}

func createTestQueue(cluster string, vhost string, newusername string, newpassword string) {

	type Queue struct {
		AutoDelete bool `json:"auto_delete"`
		Durable    bool `json:"durable"`
	}
	var queue Queue
	queue.AutoDelete = false
	queue.Durable = true
	str, err := json.Marshal(queue)
	if err != nil {
		fmt.Println("Error preparing request")
	}
	jsonStr := []byte(string(str))

	clusterinfo := clusterInfo(cluster)
	username := newusername
	password := newpassword
	auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	client := &http.Client{}
	request, _ := http.NewRequest("PUT", "http://"+clusterinfo.Url+":15672/api/queues/"+vhost+"/"+vhost+"queue", bytes.NewBuffer(jsonStr))
	request.Header.Add("Authorization", "Basic "+auth)
	request.Header.Add("Content-type", "application/json")
	response, _ := client.Do(request)
	defer response.Body.Close()
	_, _ = ioutil.ReadAll(response.Body)

}

func Encrypt(plaintext string) string {
	text := []byte(plaintext)
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	ciphertext := make([]byte, aes.BlockSize+len(text))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(crand.Reader, iv); err != nil {
		panic(err)
	}
	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], text)
	return base64.StdEncoding.EncodeToString(ciphertext)
}

func Decrypt(b64 string) string {
	text, _ := base64.StdEncoding.DecodeString(b64)
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	if len(text) < aes.BlockSize {
		panic("ciphertext too short")
	}
	iv := text[:aes.BlockSize]
	text = text[aes.BlockSize:]
	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(text, text)
	return string(text)
}

func plans(params martini.Params, r render.Render) {
	plans := make(map[string]interface{})
	plans["sandbox"] = "Dev and Testing and QA and Load testing.  May be purged regularly"
	plans["live"] = "Prod and real use. Bigger cluster.  Not purged"
	r.JSON(200, plans)

}

type tagspec struct {
	Resource string `json:"resource"`
	Name     string `json:"name"`
	Value    string `json:"value"`
}

func tag(spec tagspec, berr binding.Errors, r render.Render) {
	if berr != nil {
		fmt.Println(berr)
		errorout := make(map[string]interface{})
		errorout["error"] = berr
		r.JSON(500, errorout)
		return
	}
	fmt.Println(spec.Resource)
	fmt.Println(spec.Name)
	fmt.Println(spec.Value)
	var tags []tagspec
	_, _, _, _, tags = retreive(spec.Resource)
	tags = append(tags, spec)
	str, err := json.Marshal(tags)
	if err != nil {
		fmt.Println("Error preparing request")
	}
	jsonStr := (string(str))
	fmt.Println(jsonStr)
	uri := brokerdb
	db, err := sql.Open("postgres", uri)
	if err != nil {
		fmt.Println(err)
	}

	var nvhost string
	err = db.QueryRow("UPDATE provision set tags=$1 where vhost=$2 returning vhost;", jsonStr, spec.Resource).Scan(&nvhost)

	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(nvhost)
	err = db.Close()

	r.JSON(201, map[string]interface{}{"response": "tag added"})

}

func getvaultcreds() (u string, p string) {
	vaulttoken := os.Getenv("VAULT_TOKEN")
	vaultaddr := os.Getenv("VAULT_ADDR")
	fmt.Println(vaulttoken)
	rabbitmqsecret := os.Getenv("RABBITMQ_SECRET")
	fmt.Println(rabbitmqsecret)
	vaultaddruri := vaultaddr + "/v1/" + rabbitmqsecret
	vreq, err := http.NewRequest("GET", vaultaddruri, nil)
	vreq.Header.Add("X-Vault-Token", vaulttoken)
	vclient := &http.Client{}
	vresp, err := vclient.Do(vreq)
	if err != nil {
		fmt.Println(err)
	}
	defer vresp.Body.Close()
	bodyj, err := simplejson.NewFromReader(vresp.Body)
	fmt.Println(bodyj)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(bodyj)
	adminusername, _ := bodyj.Get("data").Get("username").String()
	adminpassword, _ := bodyj.Get("data").Get("password").String()
	keystring, _ := bodyj.Get("data").Get("key").String()
	key = []byte(keystring)
	brokerdb, _ = bodyj.Get("data").Get("brokerdb").String()
	fmt.Println(adminusername)
	fmt.Println(adminpassword)
	return adminusername, adminpassword

}

func populateClusterInfo() {
	/*
	   var sandbox ClusterInfo
	     var live    ClusterInfo

	       adminuser, adminpass := getvaultcreds()
	       fmt.Println(adminuser)
	       fmt.Println(adminpass)
	       sandbox.Url = os.Getenv("SANDBOX_RABBIT_URL")
	       sandbox.Username = adminuser
	       sandbox.Password = adminpass
	       sandbox.Amqp = os.Getenv("SANDBOX_RABBIT_AMQP")
	       sandbox.Cluster = "sandbox"

	       live.Url = os.Getenv("LIVE_RABBIT_URL")
	       live.Username = adminuser
	       live.Password = adminpass
	       live.Amqp = os.Getenv("LIVE_RABBIT_AMQP")
	       live.Cluster = "live"
	       clusters=append(clusters, sandbox)
	       clusters=append(clusters, live)
	*/
	adminuser, adminpass := getvaultcreds()
	clusterstoload := strings.Split((os.Getenv("CLUSTERS")), ",")
	fmt.Println("Loading clusters: " + strings.Join(clusterstoload, ","))
	for _, element := range clusterstoload {
		var c ClusterInfo
		c.Url = os.Getenv(strings.ToUpper(element) + "_RABBIT_URL")
		c.Username = adminuser
		c.Password = adminpass
		c.Amqp = os.Getenv(strings.ToUpper(element) + "_RABBIT_AMQP")
		c.Cluster = element
		fmt.Println(c)
		clusters = append(clusters, c)
	}

}
