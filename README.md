Upon logging in with Github, checks whether user is part of desired
organisation before setting secure cookie.

<img src="https://media.dev.unee-t.com/2019-02-18/internal-app.gif">

https://github.com/organizations/unee-t/settings/applications/978656

# How to use

	import login "github.com/unee-t/internal-github-login"

	func BasicEngine() http.Handler {
		adminHandlers := alice.New(login.RequireUneeT)
		app := login.GithubOrgOnly() // sets up special routes like GH callback
		app.Handle("/", adminHandlers.ThenFunc(indexHandler))
		return app
	}

	func indexHandler(w http.ResponseWriter, req *http.Request) {
		fmt.Fprintf(w, "For Unee-T eyes only")
	}
