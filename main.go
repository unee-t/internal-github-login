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

type Orgs []struct {
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

// New returns a new ServeMux with app routes.
func New() *http.ServeMux {
	mux := http.NewServeMux()
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
		ctx := req.Context()
		githubUser, err := github.UserFromContext(ctx)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Check user is part of the Organisation "unee-t", id 31331439
		member, err := isPartOfOrg(githubUser, 31331439)

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if !member {
			http.Error(w, "Not a member", http.StatusInternalServerError)
			return
		}

		// 2. Implement a success handler to issue some form of session
		session := sessionStore.New(sessionName)
		session.Values[sessionUserKey] = githubUser.GetName()
		session.Save(w)
		http.Redirect(w, req, "/profile", http.StatusFound)
	}
	return http.HandlerFunc(fn)
}

func isPartOfOrg(githubUser *gogithub.User, OrgID int) (member bool, err error) {

	res, err := http.Get(githubUser.GetOrganizationsURL())
	if err != nil {
		return
	}
	defer res.Body.Close()

	var orgs Orgs
	decoder := json.NewDecoder(res.Body)
	err = decoder.Decode(&orgs)
	if err != nil {
		log.WithError(err).Error("failed to decode response")
		return
	}
	for _, org := range orgs {
		log.Infof("Org: %s", org.Login)
		if org.ID == OrgID {
			return true, err
		}
	}

	return
}

// welcomeHandler shows a welcome message and login button.
func welcomeHandler(w http.ResponseWriter, req *http.Request) {
	if req.URL.Path != "/" {
		http.NotFound(w, req)
		return
	}
	if isAuthenticated(req) {
		http.Redirect(w, req, "/profile", http.StatusFound)
		return
	}
	views.ExecuteTemplate(w, "home.html", nil)
}

// profileHandler shows protected user content.
func profileHandler(w http.ResponseWriter, req *http.Request) {
	// TODO: be nice if the session was just in the context?
	session, err := sessionStore.Get(req, sessionName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	log.Infof("Session: %#v", session.Values)
	views.ExecuteTemplate(w, "profile.html", session.Values)

}

// logoutHandler destroys the session on POSTs and redirects to home.
func logoutHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method == "POST" {
		sessionStore.Destroy(w, sessionName)
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
	if _, err := sessionStore.Get(req, sessionName); err == nil {
		return true
	}
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
