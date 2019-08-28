package login

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"text/template"

	"github.com/dghubble/gologin"
	"github.com/dghubble/gologin/github"

	"github.com/apex/log"
	gogithub "github.com/google/go-github/github"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
	githubOAuth2 "golang.org/x/oauth2/github"
)

// Is this modelled somewhere else?
type GithubOrg struct {
	Login string `json:"login"`
	ID    int    `json:"id"`
}

// curl https://api.github.com/users/kaihendry/orgs # is how I looked up the org ID
var wanted = GithubOrg{
	Login: "unee-t",
	ID:    31331439,
}

var sessionSecret = os.Getenv("SESSION_SECRET")

const (
	sessionName    = "internal-github-login"
	sessionUserKey = "GithubName"
)

// sessionStore encodes and decodes session data stored in signed cookies
var store = sessions.NewCookieStore([]byte(sessionSecret), nil)

// Try https://github.com/gobuffalo/packr ?
var views = template.Must(template.ParseGlob("templates/*.html"))

// Refactor to use context instead probably
func routeLog(r *http.Request) *log.Entry {
	l := log.WithFields(log.Fields{
		"id": r.Header.Get("X-Request-Id"),
		"ua": r.UserAgent(),
	})
	return l
}

// GithubOrgOnly returns a new ServeMux with app routes.
func GithubOrgOnly() *mux.Router {
	mux := mux.NewRouter()

	mux.Handle("/profile", RequireUneeT(http.HandlerFunc(profileHandler)))

	mux.HandleFunc("/logout", logoutHandler)
	// 1. Register LoginHandler and CallbackHandler
	oauth2Config := &oauth2.Config{
		ClientID:     os.Getenv("GITHUB_CLIENT_ID"),
		ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
		RedirectURL:  fmt.Sprintf("https://%s/github/callback", os.Getenv("DOMAIN")),
		// RedirectURL: "http://localhost:3000/github/callback",
		Endpoint: githubOAuth2.Endpoint,
	}

	// stateConfig := gologin.DebugOnlyCookieConfig
	stateConfig := gologin.DefaultCookieConfig
	mux.Handle("/github/login", github.StateHandler(stateConfig, github.LoginHandler(oauth2Config, nil)))
	mux.Handle("/github/callback", github.StateHandler(stateConfig, github.CallbackHandler(oauth2Config, issueSession(), nil)))
	return mux
}

// issueSession issues a cookie session after successful Github login
func issueSession() http.Handler {
	fn := func(w http.ResponseWriter, req *http.Request) {
		log := routeLog(req)
		ctx := req.Context()
		githubUser, err := github.UserFromContext(ctx)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Check user is part of the wanted Organisation, so it can see internal stuff without WorkLink
		member, err := isPartOfOrg(githubUser, wanted)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if !member {
			err := views.ExecuteTemplate(w, "notPartOfOrg.html", wanted)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			return
		}
		log.WithField("user", githubUser.GetName()).Info("confirmed member")

		// 2. Implement a success handler to issue some form of session
		session, _ := store.Get(req, sessionName)

		// Is there a better way to define these
		store.Options.HttpOnly = true
		store.Options.Secure = true
		store.Options.MaxAge = 3600

		session.Values[sessionUserKey] = githubUser.GetName()
		err = session.Save(req, w)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		http.Redirect(w, req, "/", http.StatusFound)
	}
	return http.HandlerFunc(fn)
}

func isPartOfOrg(githubUser *gogithub.User, Org GithubOrg) (member bool, err error) {

	res, err := http.Get(githubUser.GetOrganizationsURL())
	if err != nil {
		return
	}
	defer res.Body.Close()

	var orgs []GithubOrg
	decoder := json.NewDecoder(res.Body)
	err = decoder.Decode(&orgs)
	if err != nil {
		log.WithError(err).Error("failed to decode response")
		return
	}
	for _, org := range orgs {
		log.WithField("org", org.Login).Info("part of")
		if org.ID == Org.ID {
			return true, err
		}
	}

	return
}

// profileHandler shows protected user content.
func profileHandler(w http.ResponseWriter, req *http.Request) {
	log := routeLog(req)
	session, err := store.Get(req, sessionName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	log.Infof("profile, session: %#v", session.Values)
	views.ExecuteTemplate(w, "profile.html", session.Values)

}

// logoutHandler destroys the session
func logoutHandler(w http.ResponseWriter, req *http.Request) {
	log := routeLog(req)
	session, err := store.Get(req, sessionName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	session.Options.MaxAge = -1
	err = session.Save(req, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	log.Info("deleting cookie")
	http.Redirect(w, req, "/", http.StatusFound)
}

// RequireUneeT redirects unauthenticated users to the whitelist /github/login routes
func RequireUneeT(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, req *http.Request) {
		if !strings.HasPrefix(req.URL.Path, "/github") && !isAuthenticated(req) {
			log.Warn("unauthenticated")
			err := views.ExecuteTemplate(w, "unauthenticated.html", nil)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			return
		}
		next.ServeHTTP(w, req)
	}
	return http.HandlerFunc(fn)
}

// isAuthenticated returns true if the user has a signed session cookie.
func isAuthenticated(req *http.Request) bool {
	log := routeLog(req)
	session, err := store.Get(req, sessionName)

	if err != nil {
		log.WithError(err).Warn("failed to retrieve session")
		return false
	}

	log.Infof("Session: %#v", session)

	// Is user id is set, we consider the person as logged in!?
	_, ok := session.Values[sessionUserKey]
	return ok
}
