package api

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/oauth2"

	"github.com/grafana/grafana/pkg/bus"
	"github.com/grafana/grafana/pkg/log"
	"github.com/grafana/grafana/pkg/metrics"
	"github.com/grafana/grafana/pkg/middleware"
	m "github.com/grafana/grafana/pkg/models"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/social"
)

// For development
// var (
// 	ClientID     = "1611573890337142220"
// 	ClientSecret = "CQ12lu83OfNHCG1HoO8E"
// 	AuthURL      = "https://oauth.zaloapp.com/v2/auth"
// 	TokenURL     = "https://oauth.zaloapp.com/v2/access_token"
// 	callbackUrl  = "http://dev.somonitor.zapps.vn/zalologin"
// 	QueryURL     = "http://openapi.zaloapp.com/query"
// )

// var (
// 	dbHost     = "10.30.58.44"
// 	dbPort     = "3306"
// 	dbName     = "SO_QoS"
// 	dbUser     = "so_qos"
// 	dbPassword = "fyZniUBCFXr6gBaT"
// )

// For production
var (
	//ClientID     = "1611573890337142220"
	ClientID = "1514800816656779804"
	//ClientSecret = "CQ12lu83OfNHCG1HoO8E"
	ClientSecret = "b8BvEb4N3ht86gRA7TNf"
	AuthURL      = "https://oauth.zaloapp.com/v2/auth"
	TokenURL     = "https://oauth.zaloapp.com/v2/access_token"
	callbackUrl  = "http://somonitor.zapps.vn/zalologin"
	QueryURL     = "http://openapi.zaloapp.com/query"
)

var (
	dbHost     = "10.30.58.44"
	dbPort     = "3306"
	dbName     = "SO_QoS"
	dbUser     = "so_qos"
	dbPassword = "fyZniUBCFXr6gBaT"
)

func OAuthLoginZalo(w http.ResponseWriter, r *http.Request) {
	var buffer bytes.Buffer
	buffer.WriteString(AuthURL)
	buffer.WriteString("?app_id=")
	buffer.WriteString(ClientID)
	buffer.WriteString("&redirect_uri=")
	buffer.WriteString(callbackUrl)

	url := buffer.String()
	fmt.Printf("%s\n", url)
	expire, _ := time.Parse("2014-11-12T11:45:26.371Z", "1970-11-12T11:45:26.371Z")

	defer r.Body.Close()
	http.SetCookie(w, &http.Cookie{Name: "zsid", Value: "", Domain: ".zaloapp.com", Path: "/", Expires: expire})

	fmt.Println("Request Cookies: ", r.Cookies()["zsid"])
	fmt.Printf("RespondWriter %#v\n", w.Header())
	http.Redirect(w, r, url, http.StatusFound) //302
	// http.Redirect(w, r, url, http.StatusTemporaryRedirect) //307
}

func handleZaloCallback(w http.ResponseWriter, r *http.Request, ctx *middleware.Context) {
	code := r.FormValue("code")
	var buffer bytes.Buffer
	buffer.WriteString(TokenURL)
	buffer.WriteString("?app_id=")
	buffer.WriteString(ClientID)
	buffer.WriteString("&app_secret=")
	buffer.WriteString(ClientSecret)
	buffer.WriteString("&code=")
	buffer.WriteString(code)
	buffer.WriteString("&redirect_uri=")
	buffer.WriteString(callbackUrl)

	getTokenUrl := buffer.String()

	resp, err := http.Get(getTokenUrl)
	if err != nil {
		fmt.Printf("Cannot get access token\n")
		return
	}
	defer resp.Body.Close()
	body, errReadRes := ioutil.ReadAll(resp.Body)

	if errReadRes != nil {
		fmt.Printf("Error reading response body\n")
	}

	var token map[string]interface{}
	if jsonErr := json.Unmarshal([]byte(body), &token); jsonErr != nil {
		fmt.Printf("Error parsing token\n")
	}
	fmt.Printf("Token is: %s, TTL: %d\n", token["access_token"], token["expires_in"])

	//getProfile to display:
	profile, errProfile := getProfile(token["access_token"].(string))

	if errProfile != nil {
		fmt.Printf("Error get info %s", errProfile.Error())
		ctx.Redirect(setting.AppSubUrl + "/login/zalo")
	}
	name := profile["displayName"].(string)
	// userId := profile["userId"].(string)
	avatar := profile["avatar"].(string)
	//set avatar for login user

	fmt.Printf("handleZaloCallback %s\t%s\n", name, avatar)
	// fmt.Print(profile)

	//===========Process Login, Account
	//Check displayName , if already in database => exist, else not exist
	user := checkUserNameExist(name, avatar)
	if user != nil { //===========If account already exist
		// login
		loginUserWithUser(user, ctx)
		metrics.M_Api_Login_OAuth.Inc(1)
		fmt.Printf("Valid user: %s, with info: %#v, ctx: %#v", name, *user, *ctx)
		ctx.Redirect(setting.AppSubUrl + "/")
	} else { //===========Account not exist
		fmt.Printf("Not exist user: %s", name)
		//redirect to login page, not /login/zalo
		ctx.Redirect(setting.AppSubUrl + "/login")
	}

}

func checkUserNameExist(userName string, avatar string) *m.User {
	var err error
	db, sqlErr := sql.Open("mysql", "so_qos:fyZniUBCFXr6gBaT@tcp(10.30.58.44:3306)/SO_QoS")
	if sqlErr != nil {
		fmt.Printf("Error connection mysql %s", sqlErr.Error())
	}
	defer db.Close()
	stmtOut, errSelect :=
		db.Prepare("SELECT id, version,login,email,name,password,salt,rands,company,org_id,is_admin,email_verified,theme FROM user WHERE login = ?")
	if err != nil {
		panic(err.Error()) // proper error handling instead of panic in your app
	}
	defer stmtOut.Close()

	var user m.User
	errSelect = stmtOut.QueryRow(userName).Scan(&user.Id, &user.Version, &user.Login,
		&user.Email, &user.Name, &user.Password, &user.Salt, &user.Rands,
		&user.Company, &user.OrgId, &user.IsAdmin, &user.EmailVerified, &user.Theme)
	if errSelect != nil {
		fmt.Printf("Error query mysql %s\n", errSelect.Error())
		return nil
	}

	//update avatar:
	stmtOutUpdate, errUpdate :=
		db.Prepare("UPDATE user SET email = ? WHERE login = ?")
	defer stmtOutUpdate.Close()
	ret, errUpdate := stmtOutUpdate.Exec(avatar, userName)
	roweffect, errUpdate := ret.RowsAffected()
	fmt.Printf("Row affected is: %#v\t%#v\n", roweffect, errUpdate)
	if errUpdate != nil {
		fmt.Printf("Cannot update info %s %s\n", userName, avatar)
	}

	fmt.Printf("User query result %#v\n", user)
	// login
	return &user
}

// /act=profile&appid={1}&accessTok={2}&version=2
func getProfile(access_token string) (map[string]interface{}, error) {
	var buffer bytes.Buffer
	buffer.WriteString(QueryURL)
	buffer.WriteString("?act=profile")
	buffer.WriteString("&appid=")
	buffer.WriteString(ClientID)
	buffer.WriteString("&accessTok=")
	buffer.WriteString(access_token)
	buffer.WriteString("&version=2")

	getProfileUrl := buffer.String()

	resp, err := http.Get(getProfileUrl)
	if err != nil {
		fmt.Printf("Cannot get access token\n")
		return nil, err
	}
	defer resp.Body.Close()
	body, errReadRes := ioutil.ReadAll(resp.Body)

	if errReadRes != nil {
		fmt.Printf("Error reading response body\n")
		return nil, errReadRes
	}

	var info map[string]interface{}
	if jsonErr := json.Unmarshal([]byte(body), &info); jsonErr != nil {
		fmt.Printf("Error parsing token\n")
		return nil, jsonErr
	}
	result := info["result"].(map[string]interface{})

	if result != nil {
		return result, nil
	} else {
		return nil, errors.New("Invalid response")
	}
}

func OAuthLogin(ctx *middleware.Context) {
	if setting.OAuthService == nil {
		ctx.Handle(404, "login.OAuthLogin(oauth service not enabled)", nil)
		return
	}

	name := ctx.Params(":name")
	connect, ok := social.SocialMap[name]
	if !ok {
		ctx.Handle(404, "login.OAuthLogin(social login not enabled)", errors.New(name))
		return
	}

	code := ctx.Query("code")
	if code == "" {
		ctx.Redirect(connect.AuthCodeURL("", oauth2.AccessTypeOnline))
		return
	}

	// handle call back
	token, err := connect.Exchange(oauth2.NoContext, code)
	if err != nil {
		ctx.Handle(500, "login.OAuthLogin(NewTransportWithCode)", err)
		return
	}

	log.Trace("login.OAuthLogin(Got token)")

	userInfo, err := connect.UserInfo(token)
	if err != nil {
		if err == social.ErrMissingTeamMembership {
			ctx.Redirect(setting.AppSubUrl + "/login?failedMsg=" + url.QueryEscape("Required Github team membership not fulfilled"))
		} else if err == social.ErrMissingOrganizationMembership {
			ctx.Redirect(setting.AppSubUrl + "/login?failedMsg=" + url.QueryEscape("Required Github organization membership not fulfilled"))
		} else {
			ctx.Handle(500, fmt.Sprintf("login.OAuthLogin(get info from %s)", name), err)
		}
		return
	}

	log.Trace("login.OAuthLogin(social login): %s", userInfo)

	// validate that the email is allowed to login to grafana
	if !connect.IsEmailAllowed(userInfo.Email) {
		log.Info("OAuth login attempt with unallowed email, %s", userInfo.Email)
		ctx.Redirect(setting.AppSubUrl + "/login?failedMsg=" + url.QueryEscape("Required email domain not fulfilled"))
		return
	}

	userQuery := m.GetUserByLoginQuery{LoginOrEmail: userInfo.Email}
	err = bus.Dispatch(&userQuery)

	// create account if missing
	if err == m.ErrUserNotFound {
		if !connect.IsSignupAllowed() {
			ctx.Redirect(setting.AppSubUrl + "/login")
			return
		}
		limitReached, err := middleware.QuotaReached(ctx, "user")
		if err != nil {
			ctx.Handle(500, "Failed to get user quota", err)
			return
		}
		if limitReached {
			ctx.Redirect(setting.AppSubUrl + "/login")
			return
		}
		cmd := m.CreateUserCommand{
			Login:   userInfo.Email,
			Email:   userInfo.Email,
			Name:    userInfo.Name,
			Company: userInfo.Company,
		}

		if err = bus.Dispatch(&cmd); err != nil {
			ctx.Handle(500, "Failed to create account", err)
			return
		}

		userQuery.Result = &cmd.Result
	} else if err != nil {
		ctx.Handle(500, "Unexpected error", err)
	}

	// login
	loginUserWithUser(userQuery.Result, ctx)

	metrics.M_Api_Login_OAuth.Inc(1)

	ctx.Redirect(setting.AppSubUrl + "/")
}
