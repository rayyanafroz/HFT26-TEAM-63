"""Read-side routes: tools, agents, providers, scores, graph, summary (SOT 6.7).

All of these are computed from the stored rows by ``core.views.Insights``.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from ..core.score_publisher import ScorePublisher
from ..core.views import Insights
from ..db import Database
from ..models import (
    AgentRow,
    Graph,
    Page,
    ProviderRow,
    SanctionRequest,
    SanctionResponse,
    ScoreExplain,
    Summary,
    Timeseries,
    Timestamp,
    Tool,
    VisibilityResponse,
)
from ..core.visibility import visibility_response
from .deps import get_db, get_insights, get_publisher

router = APIRouter(prefix="/api")


@router.get("/tools", response_model=Page[Tool])
def list_tools(insights: Insights = Depends(get_insights)) -> Page[Tool]:
    tools = insights.tools()
    return Page[Tool](items=tools, total=len(tools))


@router.get("/agents", response_model=Page[AgentRow])
def list_agents(insights: Insights = Depends(get_insights)) -> Page[AgentRow]:
    agents = insights.agents()
    return Page[AgentRow](items=agents, total=len(agents))


@router.get("/providers", response_model=Page[ProviderRow])
def list_providers(seen: bool | None = None, insights: Insights = Depends(get_insights)) -> Page[ProviderRow]:
    providers = insights.providers(seen=seen)
    return Page[ProviderRow](items=providers, total=len(providers))


@router.put("/providers/{provider_id}/sanction", response_model=SanctionResponse)
def set_sanction(
    provider_id: str,
    body: SanctionRequest,
    db: Database = Depends(get_db),
    insights: Insights = Depends(get_insights),
    publisher: ScorePublisher = Depends(get_publisher),
) -> SanctionResponse:
    """Approve or un-approve a provider. Every score is worked out again from the findings."""
    if insights.catalog.get(provider_id) is None:
        raise HTTPException(status_code=404, detail="provider not found")
    db.set_provider_override(provider_id, body.sanctioned)
    publisher.publish_now()                                  # other open dashboards see the new score too
    provider = insights.provider(provider_id)
    assert provider is not None
    return SanctionResponse(provider=provider, risk=insights.risk())


@router.get("/stats/summary", response_model=Summary)
def stats_summary(insights: Insights = Depends(get_insights)) -> Summary:
    return insights.summary()


@router.get("/stats/timeseries", response_model=Timeseries)
def stats_timeseries(
    bucket_s: int = Query(60, gt=0, le=86400),
    since: Timestamp | None = None,
    insights: Insights = Depends(get_insights),
) -> Timeseries:
    return insights.timeseries(bucket_s=bucket_s, since=since)


@router.get("/score/explain", response_model=ScoreExplain)
def score_explain(tool_id: str | None = None, insights: Insights = Depends(get_insights)) -> ScoreExplain:
    result = insights.score_explain(tool_id)
    if result is None:
        raise HTTPException(status_code=404, detail="tool not found")
    return result


@router.get("/graph", response_model=Graph)
def graph(insights: Insights = Depends(get_insights)) -> Graph:
    return insights.graph()


@router.get("/visibility", response_model=VisibilityResponse)
def visibility() -> VisibilityResponse:
    return visibility_response()
