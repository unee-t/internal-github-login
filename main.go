package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"text/template"

	"github.com/apex/log"
	jsonhandler "github.com/apex/log/handlers/json"
	"github.com/dghubble/gologin"
	"github.com/dghubble/gologin/github"
	"github.com/dghubble/sessions"
	gogithub "github.com/google/go-github/github"
	"golang.org/x/oauth2"
	githubOAuth2 "golang.org/x/oauth2/github"
)

// Is this modelled somewhere else?
type GithubOrg struct {
	Login            string      `json:"login"`
	ID               int         `json:"id"`
	NodeID           string      `json:"node_id"`
	URL              string      `json:"url"`
	ReposURL         string      `json:"repos_url"`
	EventsURL        string      `json:"events_url"`
	HooksURL         string      `json:"hooks_url"`
	IssuesURL        string      `json:"issues_url"`
	MembersURL       string      `json:"members_url"`
	PublicMembersURL string      `json:"public_members_url"`
	AvatarURL        string      `json:"avatar_url"`
	Description      interface{} `json:"description"`
}

// curl https://api.github.com/users/kaihendry/orgs # is how I looked up the org ID
var wanted = GithubOrg{
	Login: "unee-t",
	ID:    31331439,
}

const (
	sessionName    = "internal-github-login"
	sessionSecret  = "example cookie signing secret"
	sessionUserKey = "GithubName"
)

// sessionStore encodes and decodes session data stored in signed cookies
var sessionStore = sessions.NewCookieStore([]byte(sessionSecret), nil)
var views = template.Must(template.ParseGlob("templates/*.html"))

func init() {
	log.SetHandler(jsonhandler.Default)
}

func routeLog(r *http.Request) *log.Entry {
	l := log.WithFields(log.Fields{
		"id": r.Header.Get("X-Request-Id"),
		"ua": r.UserAgent(),
	})
	return l
}

// New returns a new ServeMux with app routes.
func New() *http.ServeMux {
	mux := http.NewServeMux()

	// TODO: Ideally want to say that any path redirects to a /login if unauthenticated
	// i.e. skip the weclomeHandler

	mux.HandleFunc("/", welcomeHandler)
	mux.Handle("/profile", requireLogin(http.HandlerFunc(profileHandler)))
	mux.HandleFunc("/logout", logoutHandler)
	// 1. Register LoginHandler and CallbackHandler
	oauth2Config := &oauth2.Config{
		ClientID:     os.Getenv("GITHUB_CLIENT_ID"),
		ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
		RedirectURL:  fmt.Sprintf("https://%s/github/callback", os.Getenv("DOMAIN")),
		Endpoint:     githubOAuth2.Endpoint,
	}

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
			http.Error(w, fmt.Sprintf("Not a member of %s", wanted.Login), http.StatusUnauthorized)
			return
		}
		log.WithField("user", githubUser.GetName()).Info("confirmed member")

		// 2. Implement a success handler to issue some form of session
		session := sessionStore.New(sessionName)
		session.Values[sessionUserKey] = githubUser.GetName()
		session.Save(w)
		http.Redirect(w, req, "/profile", http.StatusFound)
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

// welcomeHandler shows a welcome message and login button.
func welcomeHandler(w http.ResponseWriter, req *http.Request) {
	log := routeLog(req)
	if req.URL.Path != "/" {
		http.NotFound(w, req)
		return
	}
	if isAuthenticated(req) {
		log.Info("authenticated")
		http.Redirect(w, req, "/profile", http.StatusFound)
		return
	}
	log.Warn("unauthenticated")
	views.ExecuteTemplate(w, "home.html", nil)
}

// profileHandler shows protected user content.
func profileHandler(w http.ResponseWriter, req *http.Request) {
	log := routeLog(req)
	// TODO: be nice if the session was just in the context?
	session, err := sessionStore.Get(req, sessionName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	log.Infof("profile, session: %#v", session.Values)
	views.ExecuteTemplate(w, "profile.html", session.Values)

}

// logoutHandler destroys the session on POSTs and redirects to home.
func logoutHandler(w http.ResponseWriter, req *http.Request) {
	log := routeLog(req)
	if req.Method == "POST" {
		sessionStore.Destroy(w, sessionName)
		log.Warn("logging out")
	}
	http.Redirect(w, req, "/", http.StatusFound)
}

// TODO: Move into middleware?
// requireLogin redirects unauthenticated users to the login route.
func requireLogin(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, req *http.Request) {
		if !isAuthenticated(req) {
			http.Redirect(w, req, "/", http.StatusFound)
			return
		}
		next.ServeHTTP(w, req)
	}
	return http.HandlerFunc(fn)
}

// isAuthenticated returns true if the user has a signed session cookie.
func isAuthenticated(req *http.Request) bool {
	log := routeLog(req)
	if _, err := sessionStore.Get(req, sessionName); err == nil {
		log.Info("isAuthenticated: true")
		return true
	}
	log.Info("isAuthenticated: false")
	return false
}

// main creates and starts a Server listening.
func main() {
	// read credentials from environment variables if available
	err := http.ListenAndServe(":"+os.Getenv("PORT"), New())
	if err != nil {
		log.WithError(err).Fatal("error listening")
	}
}
