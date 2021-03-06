package sqlstore

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/grafana/grafana/pkg/components/simplejson"
	m "github.com/grafana/grafana/pkg/models"
)

func TestDashboardSnapshotDBAccess(t *testing.T) {

	Convey("Testing DashboardSnapshot data access", t, func() {
		InitTestDB(t)

		Convey("Given saved snaphot", func() {
			cmd := m.CreateDashboardSnapshotCommand{
				Key: "hej",
				Dashboard: simplejson.NewFromAny(map[string]interface{}{
					"hello": "mupp",
				}),
			}
			err := CreateDashboardSnapshot(&cmd)
			So(err, ShouldBeNil)

			Convey("Should be able to get snaphot by key", func() {
				query := m.GetDashboardSnapshotQuery{Key: "hej"}
				err = GetDashboardSnapshot(&query)
				So(err, ShouldBeNil)

				So(query.Result, ShouldNotBeNil)
				So(query.Result.Dashboard.Get("hello").MustString(), ShouldEqual, "mupp")
			})

		})
	})
}
