package api

import (
	"database/sql"
	"fmt"
	"net"
	"net/url"
	"strconv"

	"zaloidmw"
	"zpcommon"

	"git.apache.org/thrift.git/lib/go/thrift"
	"github.com/grafana/grafana/pkg/api/dtos"
	"github.com/grafana/grafana/pkg/bus"
	"github.com/grafana/grafana/pkg/log"
	"github.com/grafana/grafana/pkg/login"
	"github.com/grafana/grafana/pkg/metrics"
	"github.com/grafana/grafana/pkg/middleware"
	m "github.com/grafana/grafana/pkg/models"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/util"
)

const (
	VIEW_INDEX = "index"
)

func LoginView(c *middleware.Context) {
	viewData, err := setIndexViewData(c)
	if err != nil {
		c.Handle(500, "Failed to get settings", err)
		return
	}

	// viewData.Settings["googleAuthEnabled"] = setting.OAuthService.Google
	// viewData.Settings["githubAuthEnabled"] = setting.OAuthService.GitHub
	// viewData.Settings["disableUserSignUp"] = !setting.AllowUserSignUp
	// viewData.Settings["loginHint"] = setting.LoginHint
	// viewData.Settings["allowUserPassLogin"] = setting.AllowUserPassLogin

	viewData.Settings["googleAuthEnabled"] = false
	viewData.Settings["githubAuthEnabled"] = false
	viewData.Settings["zaloAuthEnabled"] = true

	viewData.Settings["disableUserSignUp"] = true
	viewData.Settings["loginHint"] = false
	viewData.Settings["allowUserPassLogin"] = true

	if !tryLoginUsingRememberCookie(c) {
		c.HTML(200, VIEW_INDEX, viewData)
		return
	}

	if redirectTo, _ := url.QueryUnescape(c.GetCookie("redirect_to")); len(redirectTo) > 0 {
		c.SetCookie("redirect_to", "", -1, setting.AppSubUrl+"/")
		c.Redirect(redirectTo)
		return
	}

	c.Redirect(setting.AppSubUrl + "/")
}

func tryLoginUsingRememberCookie(c *middleware.Context) bool {
	// Check auto-login.
	uname := c.GetCookie(setting.CookieUserName)
	if len(uname) == 0 {
		return false
	}

	isSucceed := false
	defer func() {
		if !isSucceed {
			log.Trace("auto-login cookie cleared: %s", uname)
			c.SetCookie(setting.CookieUserName, "", -1, setting.AppSubUrl+"/")
			c.SetCookie(setting.CookieRememberName, "", -1, setting.AppSubUrl+"/")
			return
		}
	}()

	userQuery := m.GetUserByLoginQuery{LoginOrEmail: uname}
	if err := bus.Dispatch(&userQuery); err != nil {
		return false
	}

	user := userQuery.Result

	// validate remember me cookie
	if val, _ := c.GetSuperSecureCookie(
		util.EncodeMd5(user.Rands+user.Password), setting.CookieRememberName); val != user.Login {
		return false
	}

	isSucceed = true
	loginUserWithUser(user, c)
	return true
}

func LoginApiPing(c *middleware.Context) {
	if !tryLoginUsingRememberCookie(c) {
		c.JsonApiErr(401, "Unauthorized", nil)
		return
	}

	c.JsonOK("Logged in")
}

func LoginPost(c *middleware.Context, cmd dtos.LoginCommand) Response {
	fmt.Printf("LoginPost user: %s\t pass: %s\n", cmd.User, cmd.Password)
	authQuery := login.LoginUserQuery{
		Username: cmd.User,
		Password: cmd.Password,
	}
	var user *m.User
	//If username != admin
	if cmd.User != "admin" {
		//Check phonenum exist
		user = checkPhoneNumExists(cmd.User)
		if user == nil {
			return ApiError(401, "You've not added, contact admin for more information", nil)
		}
		//Call ZaloIdMw for authen + update avatar if success authen
		if err := zaloIdMWAuthen(cmd.User, cmd.Password); err != true {
			return ApiError(401, "Invalid username or password", nil)
		}
		//
	} else {
		if err := bus.Dispatch(&authQuery); err != nil {
			if err == login.ErrInvalidCredentials {
				return ApiError(401, "Invalid username or password", err)
			}

			return ApiError(500, "Error while trying to authenticate user", err)
		}

		user = authQuery.User
	}

	loginUserWithUser(user, c)

	result := map[string]interface{}{
		"message": "Logged in",
	}

	if redirectTo, _ := url.QueryUnescape(c.GetCookie("redirect_to")); len(redirectTo) > 0 {
		result["redirectUrl"] = redirectTo
		c.SetCookie("redirect_to", "", -1, setting.AppSubUrl+"/")
	}

	metrics.M_Api_Login_Post.Inc(1)

	return Json(200, result)
}

//check user name exist in database
func checkPhoneNumExists(phonenumber string) *m.User {
	fmt.Printf("======checkPhoneNumExists %s\n", phonenumber)
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
	errSelect = stmtOut.QueryRow(phonenumber).Scan(&user.Id, &user.Version, &user.Login,
		&user.Email, &user.Name, &user.Password, &user.Salt, &user.Rands,
		&user.Company, &user.OrgId, &user.IsAdmin, &user.EmailVerified, &user.Theme)
	if errSelect != nil {
		fmt.Printf("Error query mysql %s\n", errSelect.Error())
		return nil
	}
	return &user
}

//call middleware to check + get info
func zaloIdMWAuthen(phonenumber string, password string) bool {
	fmt.Printf("=====zaloIdMWAuthen phone: %s\t password: %s\n", phonenumber, password)
	var protocolFactory thrift.TProtocolFactory
	// var transportFactory thrift.TTransportFactory
	var transport thrift.TTransport
	var err error

	protocolFactory = thrift.NewTBinaryProtocolFactoryDefault()
	// transportFactory = thrift.NewTFramedTransportFactory(transportFactory)
	transport, err = thrift.NewTSocket(net.JoinHostPort("10.30.22.247", "9090"))
	if err != nil {
		fmt.Println("Error connect to middleware")
		return false
	}
	// transport = transportFactory.GetTransport(transport)
	transport = thrift.NewTFramedTransport(transport)
	defer transport.Close()
	if err := transport.Open(); err != nil {
		fmt.Println("Error Open transport")
		return false
	}

	//Update client info (avatar)
	client := zaloidmw.NewZaloIdMW_SynClientFactory(transport, protocolFactory)
	phone, err798 := (strconv.ParseInt(phonenumber, 10, 64))
	if err798 != nil {
		fmt.Printf("Error convert phone to Int: %s\n", phonenumber)
		return false
	}
	zPhoneNumber := zpcommon.ZPPhoneNumber(phone)

	zaloAuthen, zAuthenErr := client.SynLoginPwdByPhone(zPhoneNumber, password, "", "", 0)
	zAuthenSessionId := zaloAuthen.SessionId
	if zAuthenErr != nil || zAuthenSessionId == "" {
		fmt.Printf("Error in SynLoginPwdByPhone %d\n", zAuthenErr)
		return false
	}
	fmt.Printf("Successful SynLoginPwdByPhone with SessionId: %s\n", zAuthenSessionId)

	//zaloidmw_shared.TUserIDResult getUserIdBySessionId(1:required zpcommon.ZPSessionID sessionId)
	zSessionId := zpcommon.ZPSessionID(zAuthenSessionId)
	zUserIdResult, zUserIdErr := client.GetUserIdBySessionId(zSessionId)
	if zUserIdErr != nil || zUserIdResult == nil {
		fmt.Printf("Error get UserId From SessionId %s\n", zAuthenSessionId)
		return false
	}

	//zaloidmw_shared.TAvatarResult getAvatarUrl(ZPUserID userId, i32 size)
	zUserAvatar, zUserAvatarErr := client.GetAvatarUrl(zUserIdResult.UserId, 1)
	if zUserAvatarErr != nil {
		fmt.Printf("Error get Avatar from UserId %#v\n", zUserAvatar)
		return true
	}
	//update avatar

	avatar := zUserAvatar.Avatars[50]
	fmt.Printf("Avatar is: %#v\t%s\n", zUserAvatar.Avatars, avatar)
	db, sqlErr := sql.Open("mysql", "so_qos:fyZniUBCFXr6gBaT@tcp(10.30.58.44:3306)/SO_QoS")
	if sqlErr != nil {
		fmt.Printf("Error connection mysql %s", sqlErr.Error())
		return false
	}
	defer db.Close()
	stmtOutUpdate, errUpdate :=
		db.Prepare("UPDATE user SET email = ? WHERE login = ?")
	defer stmtOutUpdate.Close()
	ret, errUpdate := stmtOutUpdate.Exec(avatar, phonenumber)
	if errUpdate != nil {
		fmt.Printf("Row affected is: %#v\t%#v\n", ret, errUpdate)
	}
	roweffect, errUpdate := ret.RowsAffected()
	fmt.Printf("Row affected is: %#v\t%#v\n", roweffect, errUpdate)
	if errUpdate != nil {
		fmt.Printf("Cannot update info %s %s\n", phonenumber, avatar)
	}
	return true
}
func loginUserWithUser(user *m.User, c *middleware.Context) {
	if user == nil {
		log.Error(3, "User login with nil user")
	}

	days := 86400 * setting.LogInRememberDays
	if days > 0 {
		c.SetCookie(setting.CookieUserName, user.Login, days, setting.AppSubUrl+"/")
		c.SetSuperSecureCookie(util.EncodeMd5(user.Rands+user.Password), setting.CookieRememberName, user.Login, days, setting.AppSubUrl+"/")
	}

	c.Session.Set(middleware.SESS_KEY_USERID, user.Id)
}

func Logout(c *middleware.Context) {
	c.SetCookie(setting.CookieUserName, "", -1, setting.AppSubUrl+"/")
	c.SetCookie(setting.CookieRememberName, "", -1, setting.AppSubUrl+"/")
	c.Session.Destory(c)
	c.Redirect(setting.AppSubUrl + "/login")
}
